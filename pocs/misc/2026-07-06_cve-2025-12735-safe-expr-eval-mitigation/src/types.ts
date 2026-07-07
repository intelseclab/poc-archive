/**
 * Token types recognized by the tokenizer
 */
export type TokenType =
  | 'NUMBER'
  | 'STRING'
  | 'BOOLEAN'
  | 'IDENTIFIER'
  | 'OPERATOR'
  | 'PAREN_OPEN'
  | 'PAREN_CLOSE'
  | 'FUNCTION'
  | 'COMMA'
  | 'EOF';

/**
 * Token structure
 */
export interface Token {
  type: TokenType;
  value: string | number | boolean;
  position: number;
}

/**
 * Values object for variable substitution
 */
export interface Values {
  [key: string]: any;
}

/**
 * Comparison operators
 */
export type ComparisonOperator = '==' | '!=' | '>' | '<' | '>=' | '<=';

/**
 * Logical operators
 */
export type LogicalOperator = 'and' | 'or' | 'not';
