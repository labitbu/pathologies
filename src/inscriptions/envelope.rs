use {
  super::*,
  bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::XOnlyPublicKey,
    Transaction, TxIn, Witness,
  },
  std::collections::BTreeMap,
};

use bitcoin_embed::message::Message;

pub(crate) const PROTOCOL_ID: [u8; 3] = *b"ord";
pub(crate) const BODY_TAG: [u8; 0] = [];
pub(crate) const BODY_CONTROL_BLOCK_TAG: u8 = 0;
pub(crate) const PROTOCOL_CONTROL_BLOCK_TAG: u128 = 0x42;

type Result<T, E = script::Error> = std::result::Result<T, E>;
pub type RawEnvelope = Envelope<Vec<Vec<u8>>>;
pub type ParsedEnvelope = Envelope<Inscription>;

#[derive(Default, PartialEq, Clone, Serialize, Deserialize, Debug, Eq)]
pub struct Envelope<T> {
  pub input: u32,
  pub offset: u32,
  pub payload: T,
  pub pushnum: bool,
  pub stutter: bool,
}

impl From<RawEnvelope> for ParsedEnvelope {
  fn from(envelope: RawEnvelope) -> Self {
    let body = envelope
      .payload
      .iter()
      .enumerate()
      .position(|(i, push)| i % 2 == 0 && push.is_empty());

    let mut fields: BTreeMap<&[u8], Vec<&[u8]>> = BTreeMap::new();
    let mut incomplete_field = false;

    for item in envelope.payload[..body.unwrap_or(envelope.payload.len())].chunks(2) {
      match item {
        [key, value] => fields.entry(key).or_default().push(value),
        _ => incomplete_field = true,
      }
    }

    let duplicate_field = fields.iter().any(|(_key, values)| values.len() > 1);

    let content_encoding = Tag::ContentEncoding.take(&mut fields);
    let content_type = Tag::ContentType.take(&mut fields);
    let delegate = Tag::Delegate.take(&mut fields);
    let metadata = Tag::Metadata.take(&mut fields);
    let metaprotocol = Tag::Metaprotocol.take(&mut fields);
    let parents = Tag::Parent.take_array(&mut fields);
    let pointer = Tag::Pointer.take(&mut fields);
    let properties = Tag::Properties.take(&mut fields);
    let rune = Tag::Rune.take(&mut fields);

    let unrecognized_even_field = fields
      .keys()
      .any(|tag| tag.first().map(|lsb| lsb % 2 == 0).unwrap_or_default());

    Self {
      payload: Inscription {
        body: body.map(|i| {
          envelope.payload[i + 1..]
            .iter()
            .flatten()
            .cloned()
            .collect()
        }),
        content_encoding,
        content_type,
        delegate,
        duplicate_field,
        incomplete_field,
        metadata,
        metaprotocol,
        parents,
        pointer,
        properties,
        rune,
        unrecognized_even_field,
      },
      input: envelope.input,
      offset: envelope.offset,
      pushnum: envelope.pushnum,
      stutter: envelope.stutter,
    }
  }
}

impl ParsedEnvelope {
  pub fn from_transaction(transaction: &Transaction, index: &Index) -> Vec<Self> {
    RawEnvelope::from_transaction(transaction, index)
      .into_iter()
      .map(|envelope| envelope.into())
      .collect()
  }
}

impl RawEnvelope {
  pub fn from_transaction(transaction: &Transaction, index: &Index) -> Vec<Self> {
    let mut envelope = Vec::new();

    for (i, input) in transaction.input.iter().enumerate() {
      let sat_hash = Self::sat_hash_from_input(input, index);

      if let Some(raw_envelope) = Self::from_control_block(&input.witness, i, sat_hash.as_ref()) {
        envelope.extend(raw_envelope);
      }
    }

    envelope
  }

  fn from_control_block(
    witness: &Witness,
    input_index: usize,
    sat_hash: Option<&sha256::Hash>,
  ) -> Option<Vec<Self>> {
    let legacy_target_key =
      hex::decode("96053db5b18967b5a410326ecca687441579225a6d190f398e2180deec6e429e").ok()?;

    let data = witness.iter().find_map(|item| {
      if let Some(pos) = item
        .windows(legacy_target_key.len())
        .position(|w| w == legacy_target_key.as_slice())
      {
        return Some(&item[pos + legacy_target_key.len()..]);
      }

      sat_hash.and_then(|hash| {
        let tweaked_key = Self::nums_from_tag(&hash.to_byte_array()).serialize();
        item
          .windows(33)
          .position(|w| w == tweaked_key)
          .map(|pos| &item[pos + 33..])
      })
    })?;

    let messages = Message::decode(data).ok()?;

    let mut envelope = Vec::new();

    for msg in messages {
      if msg.tag != PROTOCOL_CONTROL_BLOCK_TAG {
        continue;
      }

      let mut payload = Vec::new();
      let mut index = 0;
      let mut invalid = msg.body.len() == 1;

      while index + 1 < msg.body.len() {
        let tag = msg.body[index];

        if tag == BODY_CONTROL_BLOCK_TAG {
          payload.push(BODY_TAG.to_vec());
          payload.push(msg.body[index + 1..].to_vec());
          break;
        }

        let Ok((length, size)) = bitcoin_embed::varint::decode(&msg.body[index + 1..]) else {
          invalid = true;
          break;
        };

        if length > u32::MAX as u128 {
          invalid = true;
          break;
        }

        let length = length as usize;
        if index + 1 + size + length > msg.body.len() {
          invalid = true;
          break;
        }

        payload.push(vec![tag]);
        payload.push(msg.body[index + 1 + size..index + 1 + size + length].to_vec());
        index += 1 + size + length;
      }

      if invalid {
        continue;
      }

      envelope.push(Self {
        input: input_index.try_into().ok()?,
        offset: envelope.len().try_into().ok()?,
        payload,
        pushnum: false,
        stutter: false,
      });
    }

    (!envelope.is_empty()).then_some(envelope)
  }

  fn sat_hash_from_input(input: &TxIn, index: &Index) -> Option<sha256::Hash> {
    index
      .get_output_info(input.previous_output)
      .ok()
      .flatten()
      .and_then(|(output_info, _)| {
        output_info
          .sat_ranges
          .as_ref()
          .and_then(|ranges| ranges.iter().map(|(start, _)| *start).min())
          .map(|lowest_sat| {
            let sat_key = Self::nums_from_tag(&lowest_sat.to_le_bytes());
            sha256::Hash::hash(&sat_key.serialize())
          })
      })
  }

  fn nums_from_tag(tag: &[u8]) -> XOnlyPublicKey {
    let mut ctr = 0u32;
    loop {
      let mut eng = sha256::Hash::engine();
      eng.input(tag);
      eng.input(&ctr.to_le_bytes());
      let candidate = sha256::Hash::from_engine(eng);

      if let Ok(pk) = XOnlyPublicKey::from_slice(&candidate.to_byte_array()) {
        return pk;
      }
      ctr += 1;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn parse(witnesses: &[Witness]) -> Vec<ParsedEnvelope> {
    ParsedEnvelope::from_transaction(
      &Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: witnesses
          .iter()
          .map(|witness| TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: witness.clone(),
          })
          .collect(),
        output: Vec::new(),
      },
      &Index::open(&settings::Settings::default()).unwrap(),
    )
  }

  #[test]
  fn empty() {
    assert_eq!(parse(&[Witness::new()]), Vec::new())
  }

  #[test]
  fn ignore_key_path_spends() {
    assert_eq!(
      parse(&[Witness::from_slice(&[script::Builder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(PROTOCOL_ID)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script()
        .into_bytes()])]),
      Vec::new()
    );
  }

  #[test]
  fn ignore_key_path_spends_with_annex() {
    assert_eq!(
      parse(&[Witness::from_slice(&[
        script::Builder::new()
          .push_opcode(opcodes::OP_FALSE)
          .push_opcode(opcodes::all::OP_IF)
          .push_slice(PROTOCOL_ID)
          .push_opcode(opcodes::all::OP_ENDIF)
          .into_script()
          .into_bytes(),
        vec![0x50]
      ])]),
      Vec::new()
    );
  }

  #[test]
  fn parse_from_tapscript() {
    assert_eq!(
      parse(&[Witness::from_slice(&[
        script::Builder::new()
          .push_opcode(opcodes::OP_FALSE)
          .push_opcode(opcodes::all::OP_IF)
          .push_slice(PROTOCOL_ID)
          .push_opcode(opcodes::all::OP_ENDIF)
          .into_script()
          .into_bytes(),
        Vec::new()
      ])]),
      vec![ParsedEnvelope { ..default() }]
    );
  }

  #[test]
  fn ignore_unparsable_scripts() {
    let mut script_bytes = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script()
      .into_bytes();
    script_bytes.push(0x01);

    assert_eq!(
      parse(&[Witness::from_slice(&[script_bytes, Vec::new()])]),
      Vec::new()
    );
  }

  #[test]
  fn no_inscription() {
    assert_eq!(
      parse(&[Witness::from_slice(&[
        ScriptBuf::new().into_bytes(),
        Vec::new()
      ])]),
      Vec::new()
    );
  }

  #[test]
  fn duplicate_field() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        Tag::Nop.bytes().as_slice(),
        &[],
        &Tag::Nop.bytes(),
        &[]
      ])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          duplicate_field: true,
          ..default()
        },
        ..default()
      }]
    );
  }

  #[test]
  fn with_content_type() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        &[],
        b"ord",
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", "ord"),
        ..default()
      }]
    );
  }

  #[test]
  fn with_content_encoding() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        &[9],
        b"br",
        &[],
        b"ord",
      ])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          content_encoding: Some("br".as_bytes().to_vec()),
          ..inscription("text/plain;charset=utf-8", "ord")
        },
        ..default()
      }]
    );
  }

  #[test]
  fn with_unknown_tag() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        Tag::Nop.bytes().as_slice(),
        b"bar",
        &[],
        b"ord",
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", "ord"),
        ..default()
      }]
    );
  }

  #[test]
  fn no_body() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8"
      ])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          content_type: Some(b"text/plain;charset=utf-8".to_vec()),
          ..default()
        },
        ..default()
      }],
    );
  }

  #[test]
  fn no_content_type() {
    assert_eq!(
      parse(&[envelope(&[b"ord", &[], b"foo"])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          body: Some(b"foo".to_vec()),
          ..default()
        },
        ..default()
      }],
    );
  }

  #[test]
  fn valid_body_in_multiple_pushes() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        &[],
        b"foo",
        b"bar"
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", "foobar"),
        ..default()
      }],
    );
  }

  #[test]
  fn valid_body_in_zero_pushes() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        &[]
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", ""),
        ..default()
      }]
    );
  }

  #[test]
  fn valid_body_in_multiple_empty_pushes() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", ""),
        ..default()
      }],
    );
  }

  #[test]
  fn valid_ignore_trailing() {
    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"ord")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::all::OP_CHECKSIG)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", "ord"),
        ..default()
      }],
    );
  }

  #[test]
  fn valid_ignore_preceding() {
    let script = script::Builder::new()
      .push_opcode(opcodes::all::OP_CHECKSIG)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"ord")
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", "ord"),
        ..default()
      }],
    );
  }

  #[test]
  fn multiple_inscriptions_in_a_single_witness() {
    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"foo")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"bar")
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      vec![
        ParsedEnvelope {
          payload: inscription("text/plain;charset=utf-8", "foo"),
          ..default()
        },
        ParsedEnvelope {
          payload: inscription("text/plain;charset=utf-8", "bar"),
          offset: 1,
          ..default()
        },
      ],
    );
  }

  #[test]
  fn invalid_utf8_does_not_render_inscription_invalid() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        &[],
        &[0b10000000]
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", [0b10000000]),
        ..default()
      },],
    );
  }

  #[test]
  fn no_endif() {
    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      Vec::new(),
    );
  }

  #[test]
  fn no_op_false() {
    let script = script::Builder::new()
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      Vec::new(),
    );
  }

  #[test]
  fn empty_envelope() {
    assert_eq!(parse(&[envelope(&[])]), Vec::new());
  }

  #[test]
  fn wrong_protocol_identifier() {
    assert_eq!(parse(&[envelope(&[b"foo"])]), Vec::new());
  }

  #[test]
  fn extract_from_transaction() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"text/plain;charset=utf-8",
        &[],
        b"ord"
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("text/plain;charset=utf-8", "ord"),
        ..default()
      }],
    );
  }

  #[test]
  fn extract_from_second_input() {
    assert_eq!(
      parse(&[Witness::new(), inscription("foo", [1; 1040]).to_witness()]),
      vec![ParsedEnvelope {
        payload: inscription("foo", [1; 1040]),
        input: 1,
        ..default()
      }]
    );
  }

  #[test]
  fn extract_from_second_envelope() {
    let mut builder = script::Builder::new();
    builder = inscription("foo", [1; 100]).append_reveal_script_to_builder(builder);
    builder = inscription("bar", [1; 100]).append_reveal_script_to_builder(builder);

    assert_eq!(
      parse(&[Witness::from_slice(&[
        builder.into_script().into_bytes(),
        Vec::new()
      ])]),
      vec![
        ParsedEnvelope {
          payload: inscription("foo", [1; 100]),
          ..default()
        },
        ParsedEnvelope {
          payload: inscription("bar", [1; 100]),
          offset: 1,
          ..default()
        }
      ]
    );
  }

  #[test]
  fn inscribe_png() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::ContentType.bytes(),
        b"image/png",
        &[],
        &[1; 100]
      ])]),
      vec![ParsedEnvelope {
        payload: inscription("image/png", [1; 100]),
        ..default()
      }]
    );
  }

  #[test]
  fn chunked_data_is_parsable() {
    let mut witness = Witness::new();

    witness.push(inscription("foo", [1; 1040]).append_reveal_script(script::Builder::new()));

    witness.push([]);

    assert_eq!(
      parse(&[witness]),
      vec![ParsedEnvelope {
        payload: inscription("foo", [1; 1040]),
        ..default()
      }]
    );
  }

  #[test]
  fn round_trip_with_no_fields() {
    let mut witness = Witness::new();

    witness.push(Inscription::default().append_reveal_script(script::Builder::new()));

    witness.push([]);

    assert_eq!(
      parse(&[witness]),
      vec![ParsedEnvelope {
        payload: Inscription::default(),
        ..default()
      }],
    );
  }

  #[test]
  fn unknown_odd_fields_are_ignored() {
    assert_eq!(
      parse(&[envelope(&[&PROTOCOL_ID, &Tag::Nop.bytes(), &[0]])]),
      vec![ParsedEnvelope {
        payload: Inscription::default(),
        ..default()
      }],
    );
  }

  #[test]
  fn unknown_even_fields() {
    assert_eq!(
      parse(&[envelope(&[&PROTOCOL_ID, &[22], &[0]])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          unrecognized_even_field: true,
          ..default()
        },
        ..default()
      }],
    );
  }

  #[test]
  fn pointer_field_is_recognized() {
    assert_eq!(
      parse(&[envelope(&[&PROTOCOL_ID, &[2], &[1]])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          pointer: Some(vec![1]),
          ..default()
        },
        ..default()
      }],
    );
  }

  #[test]
  fn duplicate_pointer_field_makes_inscription_unbound() {
    assert_eq!(
      parse(&[envelope(&[&PROTOCOL_ID, &[2], &[1], &[2], &[0]])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          pointer: Some(vec![1]),
          duplicate_field: true,
          unrecognized_even_field: true,
          ..default()
        },
        ..default()
      }],
    );
  }

  #[test]
  fn tag_66_makes_inscriptions_unbound() {
    assert_eq!(
      parse(&[envelope(&[&PROTOCOL_ID, &Tag::Unbound.bytes(), &[1]])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          unrecognized_even_field: true,
          ..default()
        },
        ..default()
      }],
    );
  }

  #[test]
  fn incomplete_field() {
    assert_eq!(
      parse(&[envelope(&[&PROTOCOL_ID, &[99]])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          incomplete_field: true,
          ..default()
        },
        ..default()
      }],
    );
  }

  #[test]
  fn metadata_is_parsed_correctly() {
    assert_eq!(
      parse(&[envelope(&[&PROTOCOL_ID, &Tag::Metadata.bytes(), &[]])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          metadata: Some(Vec::new()),
          ..default()
        },
        ..default()
      }]
    );
  }

  #[test]
  fn metadata_is_parsed_correctly_from_chunks() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::Metadata.bytes(),
        &[0],
        &Tag::Metadata.bytes(),
        &[1]
      ])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          metadata: Some(vec![0, 1]),
          duplicate_field: true,
          ..default()
        },
        ..default()
      }]
    );
  }

  #[test]
  fn properties_are_parsed_correctly() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::Properties.bytes(),
        &[1, 2, 3]
      ])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          properties: Some(vec![1, 2, 3]),
          ..default()
        },
        ..default()
      }]
    );
  }

  #[test]
  fn properties_are_parsed_correctly_from_chunks() {
    assert_eq!(
      parse(&[envelope(&[
        &PROTOCOL_ID,
        &Tag::Properties.bytes(),
        &[0],
        &Tag::Properties.bytes(),
        &[1]
      ])]),
      vec![ParsedEnvelope {
        payload: Inscription {
          properties: Some(vec![0, 1]),
          duplicate_field: true,
          ..default()
        },
        ..default()
      }]
    );
  }

  #[test]
  fn pushnum_opcodes_are_parsed_correctly() {
    const PUSHNUMS: &[(opcodes::Opcode, u8)] = &[
      (opcodes::all::OP_PUSHNUM_NEG1, 0x81),
      (opcodes::all::OP_PUSHNUM_1, 1),
      (opcodes::all::OP_PUSHNUM_2, 2),
      (opcodes::all::OP_PUSHNUM_3, 3),
      (opcodes::all::OP_PUSHNUM_4, 4),
      (opcodes::all::OP_PUSHNUM_5, 5),
      (opcodes::all::OP_PUSHNUM_6, 6),
      (opcodes::all::OP_PUSHNUM_7, 7),
      (opcodes::all::OP_PUSHNUM_8, 8),
      (opcodes::all::OP_PUSHNUM_9, 9),
      (opcodes::all::OP_PUSHNUM_10, 10),
      (opcodes::all::OP_PUSHNUM_11, 11),
      (opcodes::all::OP_PUSHNUM_12, 12),
      (opcodes::all::OP_PUSHNUM_13, 13),
      (opcodes::all::OP_PUSHNUM_14, 14),
      (opcodes::all::OP_PUSHNUM_15, 15),
      (opcodes::all::OP_PUSHNUM_16, 16),
    ];

    for &(op, value) in PUSHNUMS {
      let script = script::Builder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(PROTOCOL_ID)
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(op)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();

      assert_eq!(
        parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
        vec![ParsedEnvelope {
          payload: Inscription {
            body: Some(vec![value]),
            ..default()
          },
          pushnum: true,
          ..default()
        }],
      );
    }
  }

  #[test]
  fn stuttering() {
    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      vec![ParsedEnvelope {
        payload: Default::default(),
        stutter: true,
        ..default()
      }],
    );

    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      vec![ParsedEnvelope {
        payload: Default::default(),
        stutter: true,
        ..default()
      }],
    );

    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      vec![ParsedEnvelope {
        payload: Default::default(),
        stutter: true,
        ..default()
      }],
    );

    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_AND)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID)
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      parse(&[Witness::from_slice(&[script.into_bytes(), Vec::new()])]),
      vec![ParsedEnvelope {
        payload: Default::default(),
        stutter: false,
        ..default()
      }],
    );
  }
}
