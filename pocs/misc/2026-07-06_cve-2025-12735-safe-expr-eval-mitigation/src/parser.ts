import { Tokenizer } from './tokenizer';
import { ExpressionEvaluator } from './evaluator';
import { Values } from './types';

/**
 * Parser class - Compatible API with expr-eval
 * Drop-in replacement for: import { Parser } from "expr-eval";
 */
export class Parser {
  public functions: Record<string, Function> = {};
  public consts: Record<string, any> = {};

  /**
   * Parse an expression string into an evaluable expression
   * @param expression Expression string to parse
   * @returns Parsed expression with evaluate() method
   */
  parse(expression: string): { evaluate: (variables?: Values) => any } {
    const self = this;

    return {
      evaluate(variables: Values = {}): any {
        if (expression === '') {
          return true;
        }

        try {
          // Merge constants into variables
          const allVars = { ...self.consts, ...variables };

          // Tokenize
          const tokenizer = new Tokenizer(expression);
          const tokens = tokenizer.tokenize();

          // Evaluate
          const evaluator = new ExpressionEvaluator(
            tokens,
            allVars,
            self.functions
          );
          return evaluator.evaluate();
        } catch (error: any) {
          throw new Error(
            `[SafeExprEval] Evaluation error in expression "${expression}": ${error.message}`
          );
        }
      },
    };
  }

  /**
   * Evaluate an expression directly (shorthand)
   * @param expression Expression string
   * @param variables Variables object
   * @returns Evaluation result
   */
  evaluate(expression: string, variables?: Values): any {
    return this.parse(expression).evaluate(variables);
  }
}
