import { Token, TokenType } from './types';

/**
 * Tokenizer class for expression parsing
 * Converts string expressions into tokens for evaluation
 */
export class Tokenizer {
  private input: string;
  private position: number = 0;
  private currentChar: string | null;

  constructor(input: string) {
    this.input = input.trim();
    this.currentChar = this.input.length > 0 ? this.input[0] : null;
  }

  /**
   * Advance to the next character
   */
  private advance(): void {
    this.position++;
    this.currentChar =
      this.position < this.input.length ? this.input[this.position] : null;
  }

  /**
   * Peek at the next character without advancing
   */
  private peek(offset: number = 1): string | null {
    const peekPos = this.position + offset;
    return peekPos < this.input.length ? this.input[peekPos] : null;
  }

  /**
   * Skip whitespace characters
   */
  private skipWhitespace(): void {
    while (this.currentChar !== null && /\s/.test(this.currentChar)) {
      this.advance();
    }
  }

  /**
   * Parse a number token
   */
  private number(): Token {
    let numStr = '';
    const startPos = this.position;

    while (
      this.currentChar !== null &&
      /[0-9.]/.test(this.currentChar)
    ) {
      numStr += this.currentChar;
      this.advance();
    }

    return {
      type: 'NUMBER',
      value: parseFloat(numStr),
      position: startPos,
    };
  }

  /**
   * Parse a string literal token
   */
  private string(): Token {
    const startPos = this.position;
    const quote = this.currentChar; // ' or "
    this.advance(); // Skip opening quote

    let strValue = '';
    while (this.currentChar !== null && this.currentChar !== quote) {
      if (this.currentChar === '\\') {
        this.advance();
        if (this.currentChar !== null) {
          strValue += this.currentChar;
          this.advance();
        }
      } else {
        strValue += this.currentChar;
        this.advance();
      }
    }

    if (this.currentChar === quote) {
      this.advance(); // Skip closing quote
    }

    return {
      type: 'STRING',
      value: strValue,
      position: startPos,
    };
  }

  /**
   * Parse an identifier, keyword, or boolean
   */
  private identifier(): Token {
    let idStr = '';
    const startPos = this.position;

    while (
      this.currentChar !== null &&
      /[a-zA-Z0-9_.]/.test(this.currentChar)
    ) {
      idStr += this.currentChar;
      this.advance();
    }

    // Check for booleans
    if (idStr === 'true' || idStr === 'false') {
      return {
        type: 'BOOLEAN',
        value: idStr === 'true',
        position: startPos,
      };
    }

    return {
      type: 'IDENTIFIER',
      value: idStr,
      position: startPos,
    };
  }

  /**
   * Parse an operator token
   */
  private operator(): Token {
    const startPos = this.position;
    let opStr = this.currentChar!;

    // Check for two-character operators
    const nextChar = this.peek();
    if (
      nextChar !== null &&
      ((opStr === '=' && nextChar === '=') ||
        (opStr === '!' && nextChar === '=') ||
        (opStr === '>' && nextChar === '=') ||
        (opStr === '<' && nextChar === '='))
    ) {
      opStr += nextChar;
      this.advance();
      this.advance();
    } else {
      this.advance();
    }

    return {
      type: 'OPERATOR',
      value: opStr,
      position: startPos,
    };
  }

  /**
   * Tokenize the entire input string
   */
  public tokenize(): Token[] {
    const tokens: Token[] = [];

    while (this.currentChar !== null) {
      this.skipWhitespace();

      if (this.currentChar === null) {
        break;
      }

      // Numbers (including negative numbers)
      if (/[0-9]/.test(this.currentChar)) {
        tokens.push(this.number());
        continue;
      }

      // Handle negative numbers: "-" followed by a digit
      if (
        this.currentChar === '-' &&
        this.peek() !== null &&
        /[0-9]/.test(this.peek()!) &&
        (tokens.length === 0 ||
          tokens[tokens.length - 1].type === 'PAREN_OPEN' ||
          tokens[tokens.length - 1].type === 'OPERATOR' ||
          tokens[tokens.length - 1].type === 'COMMA')
      ) {
        this.advance(); // Skip the '-'
        const numToken = this.number();
        numToken.value = -(numToken.value as number);
        tokens.push(numToken);
        continue;
      }

      // Strings
      if (this.currentChar === '"' || this.currentChar === "'") {
        tokens.push(this.string());
        continue;
      }

      // Identifiers and keywords
      if (/[a-zA-Z_]/.test(this.currentChar)) {
        tokens.push(this.identifier());
        continue;
      }

      // Parentheses
      if (this.currentChar === '(') {
        tokens.push({
          type: 'PAREN_OPEN',
          value: '(',
          position: this.position,
        });
        this.advance();
        continue;
      }

      if (this.currentChar === ')') {
        tokens.push({
          type: 'PAREN_CLOSE',
          value: ')',
          position: this.position,
        });
        this.advance();
        continue;
      }

      // Comma
      if (this.currentChar === ',') {
        tokens.push({
          type: 'COMMA',
          value: ',',
          position: this.position,
        });
        this.advance();
        continue;
      }

      // Operators
      if (/[+\-*/%<>=!]/.test(this.currentChar)) {
        tokens.push(this.operator());
        continue;
      }

      // Unknown character - skip it
      console.warn(
        `Unknown character at position ${this.position}: '${this.currentChar}'`
      );
      this.advance();
    }

    // Add EOF token
    tokens.push({
      type: 'EOF',
      value: '',
      position: this.position,
    });

    return tokens;
  }
}
