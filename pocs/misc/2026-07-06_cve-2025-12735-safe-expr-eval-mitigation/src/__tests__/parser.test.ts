import { Parser, evaluate, compile } from '../index';

describe('Parser', () => {
  let parser: Parser;

  beforeEach(() => {
    parser = new Parser();
  });

  describe('Arithmetic Operations', () => {
    test('should evaluate addition', () => {
      expect(parser.evaluate('2 + 3')).toBe(5);
      expect(parser.evaluate('10 + 20 + 30')).toBe(60);
    });

    test('should evaluate subtraction', () => {
      expect(parser.evaluate('10 - 3')).toBe(7);
      expect(parser.evaluate('100 - 50 - 25')).toBe(25);
    });

    test('should evaluate multiplication', () => {
      expect(parser.evaluate('4 * 5')).toBe(20);
      expect(parser.evaluate('2 * 3 * 4')).toBe(24);
    });

    test('should evaluate division', () => {
      expect(parser.evaluate('20 / 4')).toBe(5);
      expect(parser.evaluate('100 / 10 / 2')).toBe(5);
    });

    test('should evaluate modulo', () => {
      expect(parser.evaluate('10 % 3')).toBe(1);
      expect(parser.evaluate('17 % 5')).toBe(2);
    });

    test('should respect operator precedence', () => {
      expect(parser.evaluate('2 + 3 * 4')).toBe(14);
      expect(parser.evaluate('10 - 2 * 3')).toBe(4);
      expect(parser.evaluate('20 / 4 + 2')).toBe(7);
    });

    test('should handle parentheses', () => {
      expect(parser.evaluate('(2 + 3) * 4')).toBe(20);
      expect(parser.evaluate('10 / (2 + 3)')).toBe(2);
      expect(parser.evaluate('((2 + 3) * 4) - 5')).toBe(15);
    });

    test('should handle decimal numbers', () => {
      expect(parser.evaluate('3.14 * 2')).toBeCloseTo(6.28);
      expect(parser.evaluate('10.5 + 5.5')).toBe(16);
    });
  });

  describe('Comparison Operations', () => {
    test('should evaluate equality', () => {
      expect(parser.evaluate('5 == 5')).toBe(true);
      expect(parser.evaluate('5 == 3')).toBe(false);
      expect(parser.evaluate('"hello" == "hello"')).toBe(true);
    });

    test('should evaluate inequality', () => {
      expect(parser.evaluate('5 != 3')).toBe(true);
      expect(parser.evaluate('5 != 5')).toBe(false);
    });

    test('should evaluate greater than', () => {
      expect(parser.evaluate('10 > 5')).toBe(true);
      expect(parser.evaluate('3 > 7')).toBe(false);
      expect(parser.evaluate('5 > 5')).toBe(false);
    });

    test('should evaluate less than', () => {
      expect(parser.evaluate('3 < 7')).toBe(true);
      expect(parser.evaluate('10 < 5')).toBe(false);
      expect(parser.evaluate('5 < 5')).toBe(false);
    });

    test('should evaluate greater than or equal', () => {
      expect(parser.evaluate('10 >= 5')).toBe(true);
      expect(parser.evaluate('5 >= 5')).toBe(true);
      expect(parser.evaluate('3 >= 7')).toBe(false);
    });

    test('should evaluate less than or equal', () => {
      expect(parser.evaluate('3 <= 7')).toBe(true);
      expect(parser.evaluate('5 <= 5')).toBe(true);
      expect(parser.evaluate('10 <= 5')).toBe(false);
    });
  });

  describe('Logical Operations', () => {
    test('should evaluate AND operator', () => {
      expect(parser.evaluate('true and true')).toBe(true);
      expect(parser.evaluate('true and false')).toBe(false);
      expect(parser.evaluate('false and false')).toBe(false);
    });

    test('should evaluate OR operator', () => {
      expect(parser.evaluate('true or false')).toBe(true);
      expect(parser.evaluate('false or true')).toBe(true);
      expect(parser.evaluate('false or false')).toBe(false);
    });

    test('should evaluate NOT operator', () => {
      expect(parser.evaluate('not true')).toBe(false);
      expect(parser.evaluate('not false')).toBe(true);
    });

    test('should combine logical operators', () => {
      expect(parser.evaluate('true and true or false')).toBe(true);
      expect(parser.evaluate('false or true and true')).toBe(true);
      expect(parser.evaluate('not false and true')).toBe(true);
    });

    test('should handle complex logical expressions', () => {
      expect(parser.evaluate('(5 > 3) and (10 < 20)')).toBe(true);
      expect(parser.evaluate('(5 > 10) or (3 < 7)')).toBe(true);
      expect(parser.evaluate('not (5 == 3)')).toBe(true);
    });
  });

  describe('Variables', () => {
    test('should substitute simple variables', () => {
      expect(parser.evaluate('x + 5', { x: 10 })).toBe(15);
      expect(parser.evaluate('a * b', { a: 3, b: 4 })).toBe(12);
    });

    test('should handle multiple variables', () => {
      const vars = { price: 100, quantity: 2, tax: 0.1 };
      expect(parser.evaluate('price * quantity * (1 + tax)', vars)).toBeCloseTo(220);
    });

    test('should throw error for undefined variables', () => {
      expect(() => parser.evaluate('x + y')).toThrow('Undefined variable');
    });
  });

  describe('Constants', () => {
    test('should use constants', () => {
      parser.consts.PI = Math.PI;
      expect(parser.evaluate('PI * 2')).toBeCloseTo(6.283185);
    });

    test('should override constants with variables', () => {
      parser.consts.value = 10;
      expect(parser.evaluate('value + 5')).toBe(15);
      expect(parser.evaluate('value + 5', { value: 20 })).toBe(25);
    });
  });

  describe('Functions', () => {
    test('should call built-in functions', () => {
      parser.functions.abs = Math.abs;
      expect(parser.evaluate('abs(-5)')).toBe(5);
      expect(parser.evaluate('abs(10)')).toBe(10);
    });

    test('should call functions with multiple arguments', () => {
      parser.functions.max = Math.max;
      parser.functions.min = Math.min;
      expect(parser.evaluate('max(5, 10, 3)')).toBe(10);
      expect(parser.evaluate('min(5, 10, 3)')).toBe(3);
    });

    test('should call custom functions', () => {
      parser.functions.double = (x: number) => x * 2;
      parser.functions.add = (a: number, b: number) => a + b;
      expect(parser.evaluate('double(5)')).toBe(10);
      expect(parser.evaluate('add(3, 7)')).toBe(10);
    });

    test('should combine functions with operators', () => {
      parser.functions.round = Math.round;
      expect(parser.evaluate('round(3.7) + 2')).toBe(6);
    });

    test('should throw error for undefined functions', () => {
      expect(() => parser.evaluate('unknown(5)')).toThrow('Undefined function');
    });
  });

  describe('String Operations', () => {
    test('should handle string literals', () => {
      expect(parser.evaluate('"hello"')).toBe('hello');
      expect(parser.evaluate("'world'")).toBe('world');
    });

    test('should compare strings', () => {
      expect(parser.evaluate('"hello" == "hello"')).toBe(true);
      expect(parser.evaluate('"hello" == "world"')).toBe(false);
      expect(parser.evaluate('"hello" != "world"')).toBe(true);
    });

    test('should handle string variables', () => {
      expect(parser.evaluate('name == "John"', { name: 'John' })).toBe(true);
      expect(parser.evaluate('name == "Jane"', { name: 'John' })).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty expression', () => {
      expect(parser.evaluate('')).toBe(true);
    });

    test('should handle whitespace', () => {
      expect(parser.evaluate('  5  +  3  ')).toBe(8);
    });

    test('should handle nested parentheses', () => {
      expect(parser.evaluate('((((5))))')).toBe(5);
      expect(parser.evaluate('(((2 + 3) * 4) - 5)')).toBe(15);
    });

    test('should handle complex expressions', () => {
      const expr = '(price * quantity) * (1 + tax) - discount';
      const vars = { price: 100, quantity: 2, tax: 0.1, discount: 50 };
      expect(parser.evaluate(expr, vars)).toBeCloseTo(170);
    });
  });

  describe('parse() method', () => {
    test('should return reusable expression', () => {
      const expr = parser.parse('x * 2 + 1');
      expect(expr.evaluate({ x: 5 })).toBe(11);
      expect(expr.evaluate({ x: 10 })).toBe(21);
      expect(expr.evaluate({ x: 0 })).toBe(1);
    });

    test('should work with functions', () => {
      parser.functions.square = (x: number) => x * x;
      const expr = parser.parse('square(x) + 1');
      expect(expr.evaluate({ x: 3 })).toBe(10);
      expect(expr.evaluate({ x: 5 })).toBe(26);
    });
  });

  describe('Security', () => {
    test('should not allow code injection via eval', () => {
      // These should not execute arbitrary code
      expect(() => parser.evaluate('eval("1+1")')).toThrow();
      expect(() => parser.evaluate('Function("return 1+1")()')).toThrow();
      expect(() => parser.evaluate('process.exit()')).toThrow();
    });

    test('should safely handle malformed expressions', () => {
      expect(() => parser.evaluate('2 +')).toThrow();
      expect(() => parser.evaluate('* 5')).toThrow();
      expect(() => parser.evaluate('(((5)')).not.toThrow(); // Missing closing paren
    });
  });
});

describe('Standalone Functions', () => {
  describe('evaluate()', () => {
    test('should evaluate expressions directly', () => {
      expect(evaluate('2 + 3')).toBe(5);
      expect(evaluate('10 * 5')).toBe(50);
    });

    test('should accept variables', () => {
      expect(evaluate('x + y', { x: 10, y: 20 })).toBe(30);
    });
  });

  describe('compile()', () => {
    test('should create reusable function', () => {
      const fn = compile('a * b + c');
      expect(fn({ a: 2, b: 3, c: 1 })).toBe(7);
      expect(fn({ a: 5, b: 2, c: 10 })).toBe(20);
    });

    test('should work with complex expressions', () => {
      const fn = compile('(price * quantity) * (1 + tax)');
      expect(fn({ price: 100, quantity: 2, tax: 0.1 })).toBeCloseTo(220);
      expect(fn({ price: 50, quantity: 3, tax: 0.15 })).toBeCloseTo(172.5);
    });
  });
});

describe('Real-world Scenarios', () => {
  test('should calculate shipping cost', () => {
    const parser = new Parser();
    parser.consts.BASE_RATE = 5;
    parser.functions.max = Math.max;

    const expr = parser.parse('BASE_RATE + max(0, weight - 1) * 2');
    expect(expr.evaluate({ weight: 0.5 })).toBe(5);
    expect(expr.evaluate({ weight: 1 })).toBe(5);
    expect(expr.evaluate({ weight: 3 })).toBe(9);
  });

  test('should validate business rules', () => {
    const parser = new Parser();
    const rule = parser.parse('age >= 18 and income > 30000 and score >= 700');

    expect(rule.evaluate({ age: 25, income: 50000, score: 750 })).toBe(true);
    expect(rule.evaluate({ age: 17, income: 50000, score: 750 })).toBe(false);
    expect(rule.evaluate({ age: 25, income: 25000, score: 750 })).toBe(false);
  });

  test('should calculate discount', () => {
    const parser = new Parser();
    parser.functions.min = Math.min;

    const expr = parser.parse(
      'total * min(0.3, loyalty_years * 0.05)'
    );

    expect(expr.evaluate({ total: 100, loyalty_years: 2 })).toBe(10);
    expect(expr.evaluate({ total: 100, loyalty_years: 10 })).toBe(30);
  });
});
