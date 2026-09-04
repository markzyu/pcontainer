use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use strum::EnumCount;

#[allow(dead_code)]
/// These could be waiting for literals or waiting for other basic BNF terms
#[derive(Clone, Copy, Debug, EnumCount, PartialEq, Eq, PartialOrd, Ord)]
enum JsonParserYieldReason {
  EmptyString,
  LiteralArrayStart,
  LiteralArrayEnd,
  LiteralObjectStart,
  LiteralObjectEnd,
  LiteralStringStart,
  LiteralStringEnd,
  LiteralColon,
  LiteralComma,
  LiteralPeriod,
  LiteralTrue,
  LiteralFalse,
  LiteralNull,
  LiteralSlash,
  LiteralBackwardsSlash,
  LiteralHexEscapeChar,
  RegexCharAnyExceptQuoteOrSlash,
  RegexEscapedCharAfterSlash,
  RegexCharExponent,
  RegexCharInHex,
  RegexCharInDigit,
  RegexCharNumberSign,
  RegexCharOneToNine,
  RegexCharWhitespace
}

type JsonParserYieldResponse = String;

type AsyncRuntime = krsm::AsyncRuntime<JsonParserYieldReason, JsonParserYieldResponse>;

#[allow(dead_code)]
#[derive(Debug)]
enum Json {
  Object(HashMap<String, Json>),
  Array(Vec<Json>),
  Number(String),
  String(String),
  Boolean(bool),
  Null
}

/// This is a state machine that is written in the exact same way as a BNF grammar.
struct JsonParser<'a> {
  runtime: &'a AsyncRuntime,
  

  /// This prevents the parser from quitting too early
  level: RefCell<usize>,
}

impl<'a> JsonParser<'a> {
  async fn parse(&self) -> Json {
    self.parse_element().await
  }
  
  /// <value> ::= <object> | <array> | <string> | <number> | <boolean> | <null>
  async fn parse_value(&self) -> Json {
    futures_lite::future::or(
      futures_lite::future::or(
        self.parse_object(),
        futures_lite::future::or(
          self.parse_array(),
          self.parse_string_value(),
        )
      ),
      futures_lite::future::or(
        self.parse_number(),
        futures_lite::future::or(
          self.parse_boolean(),
          self.parse_null()
        )
      ),
    ).await
  }

  /// <object> ::= "{" <whitespaces> "}" | "{" <members> "}"
  async fn parse_object(&self) -> Json {
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralObjectStart).await;
    let result = futures_lite::future::or(
      async {
        self.parse_whitespaces().await;
        Json::Object(HashMap::default())
      },
      async {
        Json::Object(Box::pin(self.parse_members()).await)
      }
    ).await;
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralObjectEnd).await;
    result
  }

  /// <members> ::= <member> | <member> "," <members>
  async fn parse_members(&self) -> HashMap<String, Json> {
    futures_lite::future::or(
      async {
        let (key, value) = self.parse_member().await;
        HashMap::from([(key, value)])
      },
      async {
        let (key, value) = self.parse_member().await;
        self.runtime.new_pending_future(JsonParserYieldReason::LiteralComma).await;
        let mut map2 = Box::pin(self.parse_members()).await;
        map2.insert(key, value);
        map2
      }
    ).await
  }

  /// <member> ::= <whitespaces> <string> <whitespaces> ":" <value>
  async fn parse_member(&self) -> (String, Json) {
    self.parse_whitespaces().await;
    let key = self.parse_string().await;
    self.parse_whitespaces().await;
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralColon).await;
    let value = self.parse_element().await;
    (key, value)
  }

  /// <array> ::= "[" <whitespaces> "]" | "[" <elements> "]"
  async fn parse_array(&self) -> Json {
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralArrayStart).await;
    let result = futures_lite::future::or(
      async {
        self.parse_whitespaces().await;
        Json::Array(Vec::default())
      },
      async {
        Json::Array(self.parse_elements().await)
      }
    ).await;
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralArrayEnd).await;
    result
  }

  /// wrapper of parse_elements_reversed
  async fn parse_elements(&self) -> Vec<Json> {
    let mut list = self.parse_elements_reversed().await;
    list.reverse();
    list
  }

  /// <elements> ::= <element> | <element> "," <elements>
  async fn parse_elements_reversed(&self) -> Vec<Json> {
    futures_lite::future::or(
      async {
        let item = self.parse_element().await;
        vec![item]
      },
      async {
        let item = self.parse_element().await;
        self.runtime.new_pending_future(JsonParserYieldReason::LiteralComma).await;
        let mut list = Box::pin(self.parse_elements_reversed()).await;
        list.push(item);
        list
      }
    ).await
  }

  /// <element> ::= <whitespaces> <value> <whitespaces>
  async fn parse_element(&self) -> Json {
    self.parse_whitespaces().await;
    let value = Box::pin(self.parse_value()).await;
    self.parse_whitespaces().await;
    value
  }

  /// Wrapper of parse_string (different return type)
  async fn parse_string_value(&self) -> Json {
    Json::String(self.parse_string().await)
  }

  /// <string> ::= '"' <characters> '"'
  async fn parse_string(&self) -> String {
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralStringStart).await;
    let mut reversed = self.parse_characters_reversed().await;
    reversed.reverse();
    let result = reversed.into_iter().collect::<String>();
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralStringEnd).await;
    result
  }

  /// <characters> ::= "" | <character> | <character> <characters>
  async fn parse_characters_reversed(&self) -> Vec<char> {
    futures_lite::future::or(
      async {
        self.runtime.new_pending_future(JsonParserYieldReason::EmptyString).await;
        vec![]
      },
      async {
        let char = self.parse_character().await;
        let mut list = Box::pin(self.parse_characters_reversed()).await;
        list.push(char);
        list
      }
    ).await
  }

  /// helper function to convert a string to a character
  fn str_to_char(&self, str: &str) -> char {
    str.chars().next().unwrap()
  }
  
  /// <character> ::= <regex_char_any_except_quote_or_slash> | <literal_slash> <regex_escaped_char_after_slash> | <literal_slash> "u" <hex> <hex> <hex> <hex>
  async fn parse_character(&self) -> char {
    futures_lite::future::or(
      async {
        let str = self.runtime.new_pending_future(JsonParserYieldReason::RegexCharAnyExceptQuoteOrSlash).await;
        self.str_to_char(&str)
      },
      futures_lite::future::or(
        async {
          self.runtime.new_pending_future(JsonParserYieldReason::LiteralSlash).await;
          let str = self.runtime.new_pending_future(JsonParserYieldReason::RegexEscapedCharAfterSlash).await;
          self.str_to_char(&str)
        },
        async {
          self.runtime.new_pending_future(JsonParserYieldReason::LiteralSlash).await;
          self.runtime.new_pending_future(JsonParserYieldReason::LiteralHexEscapeChar).await;
          let hex1 = self.runtime.new_pending_future(JsonParserYieldReason::RegexCharInHex).await;
          let hex2 = self.runtime.new_pending_future(JsonParserYieldReason::RegexCharInHex).await;
          let hex3 = self.runtime.new_pending_future(JsonParserYieldReason::RegexCharInHex).await;
          let hex4 = self.runtime.new_pending_future(JsonParserYieldReason::RegexCharInHex).await;
          let hex_str = format!("0x{}{}{}{}", hex1, hex2, hex3, hex4);
          let hex_val = u32::from_str_radix(&hex_str, 16).unwrap();
          char::from_u32(hex_val).unwrap()
        }
      )
    ).await
  }

  /// <number> ::= <integer> <fraction> <exponent>
  async fn parse_number(&self) -> Json {
    let integer = self.parse_integer().await;
    let fraction = self.parse_fraction().await;
    let exponent = self.parse_exponent().await;
    Json::Number(format!("{}{}{}", integer, fraction, exponent))
  }

  /// <integer> ::= <sign> <digits> | <digits>
  async fn parse_integer(&self) -> String {
    futures_lite::future::or(
      async {
        let sign = futures_lite::future::or(
          self.runtime.new_pending_future(JsonParserYieldReason::RegexCharNumberSign),
          self.runtime.new_pending_future(JsonParserYieldReason::EmptyString),
        ).await;
        let digits = self.parse_digits().await;
        format!("{}{}", sign, digits)
      },
      self.parse_digits(),
    ).await
  }

  /// <digits> ::= <digit> | <digit> <digits>
  async fn parse_digits(&self) -> String {
    futures_lite::future::or(
      self.runtime.new_pending_future(JsonParserYieldReason::RegexCharInDigit),
      async {
        let digit = self.runtime.new_pending_future(JsonParserYieldReason::RegexCharInDigit).await;
        let digits = Box::pin(self.parse_digits()).await;
        format!("{}{}", digit, digits)
      },
    ).await
  }

  /// <fraction> ::= "." <digits> | ""
  async fn parse_fraction(&self) -> String {
    futures_lite::future::or(
      self.runtime.new_pending_future(JsonParserYieldReason::EmptyString),
      async {
        self.runtime.new_pending_future(JsonParserYieldReason::LiteralPeriod).await;
        let digits = self.parse_digits().await;
        format!("{}{}", ".", digits)
      }
    ).await
  }

  /// <exponent> ::= "e" <digits> | "E" <digits> | ""
  async fn parse_exponent(&self) -> String {
    futures_lite::future::or(
      self.runtime.new_pending_future(JsonParserYieldReason::EmptyString),
      async {
        let exp = self.runtime.new_pending_future(JsonParserYieldReason::RegexCharExponent).await;
        let digits = self.parse_digits().await;
        format!("{}{}", exp, digits)
      }
    ).await
  }

  /// <whitespaces> ::= "" | <regex_char_whitespace> <whitespaces>
  async fn parse_whitespaces(&self) {
    futures_lite::future::or(
      async {
        self.runtime.new_pending_future(JsonParserYieldReason::EmptyString).await;
      },
      async {
        self.runtime.new_pending_future(JsonParserYieldReason::RegexCharWhitespace).await;
        Box::pin(self.parse_whitespaces()).await;
      }
    ).await;
  }

  /// <boolean> ::= "true" | "false"
  async fn parse_boolean(&self) -> Json {
    futures_lite::future::or(
      async {
        self.runtime.new_pending_future(JsonParserYieldReason::LiteralTrue).await;
        Json::Boolean(true)
      },
      async {
        self.runtime.new_pending_future(JsonParserYieldReason::LiteralFalse).await;
        Json::Boolean(false)
      }
    ).await
  }

  /// <null> ::= "null"
  async fn parse_null(&self) -> Json {
    self.runtime.new_pending_future(JsonParserYieldReason::LiteralNull).await;
    Json::Null
  }
}

fn run_parser(full_str: &str) -> Result<Json, String> {
  let runtime = AsyncRuntime::new().map_err(|e| format!("{:?}", e))?;
  let parser = JsonParser { runtime: &runtime, level: RefCell::new(0) };
  let mut future = parser.parse();
  let mut index = 0;
  loop {
    let result = unsafe { runtime.run_async_step(&mut future).unwrap() };
    if let Some(json) = result {
      return Ok(json);
    }

    // Async step yielded. Handle the yield reason by checking the type of the next character.
    // And, if there is no more input, return an error.
    if index >= full_str.len() {
      loop {
        let unblock_reason = runtime.check_pending_reasons(|reason| match reason {
          Some(JsonParserYieldReason::EmptyString) => true,
          _ => false
        });
        if unblock_reason.is_none() {
          break;
        } else {
          runtime.unblock_futures(JsonParserYieldReason::EmptyString, "".to_string());
          let result = unsafe { runtime.run_async_step(&mut future).unwrap() };
          if let Some(json) = result {
            return Ok(json);
          }
        }
      }
      return Err("Unexpected end of input".to_string());
    }

    let single_char = &full_str[index..index+1];

    let unblock_reason = runtime.check_pending_reasons(|reason| match reason {
      Some(JsonParserYieldReason::LiteralArrayStart) => single_char == "[",
      Some(JsonParserYieldReason::LiteralArrayEnd) => single_char == "]",
      Some(JsonParserYieldReason::LiteralObjectStart) => single_char == "{",
      Some(JsonParserYieldReason::LiteralObjectEnd) => single_char == "}",
      Some(JsonParserYieldReason::LiteralStringStart) => &full_str[index..index+1] == "\"",
      Some(JsonParserYieldReason::LiteralStringEnd) => single_char == "\"",
      Some(JsonParserYieldReason::LiteralColon) => single_char == ":",
      Some(JsonParserYieldReason::LiteralComma) => single_char == ",",
      Some(JsonParserYieldReason::LiteralPeriod) => single_char == ".",
      Some(JsonParserYieldReason::LiteralTrue) => full_str[index..].starts_with("true"),
      Some(JsonParserYieldReason::LiteralFalse) => full_str[index..].starts_with("false"),
      Some(JsonParserYieldReason::LiteralNull) => full_str[index..].starts_with("null"),
      Some(JsonParserYieldReason::LiteralSlash) => single_char == "/",
      Some(JsonParserYieldReason::LiteralBackwardsSlash) => single_char == "\\",
      Some(JsonParserYieldReason::LiteralHexEscapeChar) => single_char == "u",
      Some(JsonParserYieldReason::RegexCharAnyExceptQuoteOrSlash) => single_char != "\"" && single_char != "\\",
      Some(JsonParserYieldReason::RegexEscapedCharAfterSlash) => "\"\\/bfnrtu".contains(single_char),
      Some(JsonParserYieldReason::RegexCharExponent) => single_char == "e" || single_char == "E",
      Some(JsonParserYieldReason::RegexCharInHex) => "0123456789abcdefABCDEF".contains(single_char),
      Some(JsonParserYieldReason::RegexCharInDigit) => "0123456789".contains(single_char),
      Some(JsonParserYieldReason::RegexCharNumberSign) => "+-".contains(single_char),
      Some(JsonParserYieldReason::RegexCharOneToNine) => "123456789".contains(single_char),
      Some(JsonParserYieldReason::RegexCharWhitespace) => " \t\n\r".contains(single_char),
      Some(JsonParserYieldReason::EmptyString) => true,
      _ => false,
    });

    let Some(unblock_reason) = unblock_reason else {
      return Err(format!("Unexpected character: {}", single_char));
    };

    let mut response = "".to_string();
    if unblock_reason == JsonParserYieldReason::LiteralTrue {
      response = "true".to_string();
      index += 4;
    } else if unblock_reason == JsonParserYieldReason::LiteralFalse {
      response = "false".to_string();
      index += 5;
    } else if unblock_reason == JsonParserYieldReason::LiteralNull {
      response = "null".to_string();
      index += 4;
    } else if unblock_reason != JsonParserYieldReason::EmptyString {
      response = single_char.to_string();
      index += 1;
    }

    // Note: This is technically wrong for LiteralTrue, LiteralFalse, LiteralNull. But it's enough for this example.
    println!("Debug, unblocking {:?}, str {}", unblock_reason, response);
    runtime.unblock_futures(unblock_reason, response);
  }
}

fn main() -> std::io::Result<()> {
  let mut input = String::new();
  std::io::stdin().read_line(&mut input)?;
  let result = run_parser(&input).unwrap();
  println!("Parsed result: {:?}", result);
  Ok(())
}