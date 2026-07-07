import { Token, TokenType, ComparisonOperator, Values } from './types';
import { Tokenizer } from './tokenizer';

/**
 * Expression evaluator class
 * Evaluates tokenized expressions safely without using eval()
 */
export class ExpressionEvaluator {
  private tokens: Token[];
  private currentTokenIndex: number = 0;
  private variables: Record<string, any>;
  private functions: Record<string, Function>;

  constructor(
    tokens: Token[],
    variables: Record<string, any>,
    functions: Record<string, Function>
  ) {
    this.tokens = tokens;
    this.variables = variables;
    this.functions = functions;
  }

  /**
   * Get the current token
   */
  private currentToken(): Token {
    return this.tokens[this.currentTokenIndex];
  }

  /**
   * Consume the current token and move to the next
   */
  private consume(): Token {
    const token = this.currentToken();
    this.currentTokenIndex++;
    return token;
  }

  /**
   * Evaluate the expression
   */
  public evaluate(): any {
    return this.parseOr();
  }

  /**
   * Parse logical OR expressions
   */
  private parseOr(): any {
    let left = this.parseAnd();

    while (
      this.currentToken().type === 'IDENTIFIER' &&
      this.currentToken().value === 'or'
    ) {
      this.consume();
      const right = this.parseAnd();
      left = this.toBool(left) || this.toBool(right);
    }

    return left;
  }

  /**
   * Parse logical AND expressions
   */
  private parseAnd(): any {
    let left = this.parseNot();

    while (
      this.currentToken().type === 'IDENTIFIER' &&
      this.currentToken().value === 'and'
    ) {
      this.consume();
      const right = this.parseNot();
      left = this.toBool(left) && this.toBool(right);
    }

    return left;
  }

  /**
   * Parse logical NOT expressions
   */
  private parseNot(): any {
    if (
      this.currentToken().type === 'IDENTIFIER' &&
      this.currentToken().value === 'not'
    ) {
      this.consume();
      return !this.toBool(this.parseNot());
    }

    return this.parseComparison();
  }

  /**
   * Parse comparison expressions
   */
  private parseComparison(): any {
    let left = this.parseAdditive();

    const token = this.currentToken();
    if (token.type === 'OPERATOR') {
      const op = token.value as ComparisonOperator;
      if (['==', '!=', '>', '<', '>=', '<='].includes(op)) {
        this.consume();
        const right = this.parseAdditive();
        return this.compare(left, op, right);
      }
    }

    return left;
  }

  /**
   * Parse additive expressions (+ and -)
   */
  private parseAdditive(): any {
    let left = this.parseMultiplicative();

    while (
      this.currentToken().type === 'OPERATOR' &&
      (this.currentToken().value === '+' || this.currentToken().value === '-')
    ) {
      const op = this.consume().value as string;
      const right = this.parseMultiplicative();

      if (op === '+') {
        left = this.toNumber(left) + this.toNumber(right);
      } else {
        left = this.toNumber(left) - this.toNumber(right);
      }
    }

    return left;
  }

  /**
   * Parse multiplicative expressions (*, /, %)
   */
  private parseMultiplicative(): any {
    let left = this.parsePrimary();

    while (
      this.currentToken().type === 'OPERATOR' &&
      ['*', '/', '%'].includes(this.currentToken().value as string)
    ) {
      const op = this.consume().value as string;
      const right = this.parsePrimary();

      if (op === '*') {
        left = this.toNumber(left) * this.toNumber(right);
      } else if (op === '/') {
        left = this.toNumber(left) / this.toNumber(right);
      } else {
        left = this.toNumber(left) % this.toNumber(right);
      }
    }

    return left;
  }

  /**
   * Parse primary expressions (literals, identifiers, function calls, parenthesized expressions)
   */
  private parsePrimary(): any {
    const token = this.currentToken();

    // Numbers
    if (token.type === 'NUMBER') {
      this.consume();
      return token.value;
    }

    // Strings
    if (token.type === 'STRING') {
      this.consume();
      return token.value;
    }

    // Booleans
    if (token.type === 'BOOLEAN') {
      this.consume();
      return token.value;
    }

    // Parenthesized expressions
    if (token.type === 'PAREN_OPEN') {
      this.consume();
      const value = this.parseOr();
      if (this.currentToken().type === 'PAREN_CLOSE') {
        this.consume();
      }
      return value;
    }

    // Identifiers (variables or function calls)
    if (token.type === 'IDENTIFIER') {
      const name = token.value as string;
      this.consume();

      // Check if it's a function call
      if (this.currentToken().type === 'PAREN_OPEN') {
        return this.parseFunctionCall(name);
      }

      // Variable lookup
      if (name in this.variables) {
        return this.variables[name];
      }

      throw new Error(`Undefined variable: ${name}`);
    }

    throw new Error(`Unexpected token: ${token.type} at position ${token.position}`);
  }

  /**
   * Parse function call
   */
  private parseFunctionCall(functionName: string): any {
    // Consume opening parenthesis
    this.consume();

    // Parse arguments
    const args: any[] = [];
    while (this.currentToken().type !== 'PAREN_CLOSE' && this.currentToken().type !== 'EOF') {
      args.push(this.parseOr());

      if (this.currentToken().type === 'COMMA') {
        this.consume();
      }
    }

    // Consume closing parenthesis
    if (this.currentToken().type === 'PAREN_CLOSE') {
      this.consume();
    }

    // Call the function
    if (functionName in this.functions) {
      return this.functions[functionName](...args);
    }

    throw new Error(`Undefined function: ${functionName}`);
  }

  /**
   * Compare two values
   */
  private compare(left: any, op: ComparisonOperator, right: any): boolean {
    switch (op) {
      case '==':
        return left == right;
      case '!=':
        return left != right;
      case '>':
        return this.toNumber(left) > this.toNumber(right);
      case '<':
        return this.toNumber(left) < this.toNumber(right);
      case '>=':
        return this.toNumber(left) >= this.toNumber(right);
      case '<=':
        return this.toNumber(left) <= this.toNumber(right);
      default:
        throw new Error(`Unknown operator: ${op}`);
    }
  }

  /**
   * Convert value to boolean
   */
  private toBool(value: any): boolean {
    if (typeof value === 'boolean') {
      return value;
    }
    if (typeof value === 'number') {
      return value !== 0;
    }
    if (typeof value === 'string') {
      return value.length > 0;
    }
    return Boolean(value);
  }

  /**
   * Convert value to number
   */
  private toNumber(value: any): number {
    if (typeof value === 'number') {
      return value;
    }
    if (typeof value === 'boolean') {
      return value ? 1 : 0;
    }
    if (typeof value === 'string') {
      const num = parseFloat(value);
      return isNaN(num) ? 0 : num;
    }
    return 0;
  }
}

/**
 * Helper function to evaluate an expression directly
 */
export function evaluate(expression: string, variables?: Values): any {
  const tokenizer = new Tokenizer(expression);
  const tokens = tokenizer.tokenize();
  const evaluator = new ExpressionEvaluator(tokens, variables || {}, {});
  return evaluator.evaluate();
}

/**
 * Helper function to compile an expression for reuse
 */
export function compile(expression: string): (variables?: Values) => any {
  const tokenizer = new Tokenizer(expression);
  const tokens = tokenizer.tokenize();

  return (variables?: Values) => {
    const evaluator = new ExpressionEvaluator(tokens, variables || {}, {});
    return evaluator.evaluate();
  };
}
