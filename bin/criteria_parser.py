from parsec.src.parsec import *

class Context:
    def __init__(self, record):
        self.record = record
        self.debug = []

class Expr:
    def evaluate(self, context):
        raise NotImplementedError("subclass must override evaluate")
    def ast(self, indent = ""):
        raise NotImplementedError("subclass must override evaluate")

class LiteralExpr(Expr):
    def __init__(self, value):
        self.value = value
    def evaluate(self, context):
        return self.value
    def __str__(self):
        return "LiteralExpr(" + str(self.value) + ")"
    def ast(self, indent = ""):
        return indent + str(self.value)

class ArrayExpr(Expr):
    def __init__(self, elementExprs):
        self.elementExprs = elementExprs
    def evaluate(self, context):
        return [expr.evaluate(context) for expr in self.elementExprs]
    def __str__(self):
        return "ArrayExpr([" + ', '.join(map(lambda e: str(e), self.elementExprs)) + "])"
    def ast(self, indent = ""):
        inner_indent = indent + "  "
        return (
            indent + "[\n"
            + ''.join(map(lambda e: inner_indent + e.ast(inner_indent) + "\n", self.elementExprs)) + "\n"
            + indent + "]"
        )

class SetExpr(Expr):
    def __init__(self, expr):
        self.expr = expr
    def evaluate(self, context):
        arr = self.expr.evaluate(context)
        # must evaluate to an array
        return set(arr)
    def __str__(self):
        return "SetExpr(" + str(self.expr) + ")"
    def ast(self, indent = ""):
        inner_indent = indent + "  "
        return (
            indent + "set(\n"
            + self.expr.ast(inner_indent) + "\n"
            + indent + ")"
        )

class FieldExpr(Expr):
    def __init__(self, fieldExpr):
        self.fieldExpr = fieldExpr
    def evaluate(self, context):
        field = self.fieldExpr.evaluate(context)
        if field in context.record:
            context.debug.append("record['%s'] => %s" % (field, context.record[field]))
            return context.record[field]
        else:
            context.debug.append("record['%s'] => None" % field)
            return None
    def __str__(self):
        return "FieldExpr(" + str(self.fieldExpr) + ")"
    def ast(self, indent = ""):
        return indent + "record['%s']" % str(self.fieldExpr)

class MatchExpr(Expr):
    import re
    cidr_pat = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$')
    ip_pat = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    def __init__(self, functionName, patternExpr, stringExpr):
        self.functionName = functionName
        self.patternExpr = patternExpr
        self.stringExpr = stringExpr
    def match_to_ip(self, m):
        return ((int(m.group(1)) << 24) | (int(m.group(2)) << 16) | (int(m.group(3)) << 8) | int(m.group(4)))
    def evaluate(self, context):
        pattern = self.patternExpr.evaluate(context)
        s = self.stringExpr.evaluate(context)
        if self.functionName == 'search':
            match_obj = re.search(pattern, s)
            context.debug.append("%s(%s, %s) => %s" % (self.functionName, pattern, s, str(match_obj)))
            return match_obj is not None
        elif self.functionName == 'match':
            match_obj = re.match(pattern, s)
            context.debug.append("%s(%s, %s) => %s" % (self.functionName, pattern, s, str(match_obj)))
            return match_obj is not None
        elif self.functionName == 'cidrmatch':
            m = self.cidr_pat.match(pattern.strip())
            if not m:
                raise RuntimeError('invalid cidr: %s' % pattern)
            else:
                cidr_ip_int = self.match_to_ip(m)
                mask_count = int(m.group(5))
                mask = ((1 << mask_count) - 1) << (32 - mask_count)
                m1 = self.ip_pat.match(s.strip())
                if not m1:
                    raise RuntimeError('invalid ip: %s' % s)
                else:
                    ip_int = self.match_to_ip(m1)
                    result = (ip_int & mask) == (cidr_ip_int & mask)
                    context.debug.append("%s(%s, %s) => %s" % (self.functionName, pattern, s, str(result)))
                    return result
        else:
            raise RuntimeError('invalid function name: %s' % self.functionName)
    def __str__(self):
        return "MatchExpr(%s,  %s, %s)" % (self.functionName, self.patternExpr, self.stringExpr)
    def ast(self, indent = ""):
        inner_indent = indent + "  "
        return (
            indent + "(" + self.functionName + "\n"
            + self.patternExpr.ast(inner_indent) + "\n"
            + self.stringExpr.ast(inner_indent) + "\n"
            + indent + ")"
        )

class ComparisonExpr(Expr):
    def __init__(self, leftExpr, rightExpr, opStr, compareFun):
        self.leftExpr = leftExpr
        self.rightExpr = rightExpr
        self.opStr = opStr
        self.compareFun = compareFun
    def evaluate(self, context):
        import numbers
        left = self.leftExpr.evaluate(context)
        right = self.rightExpr.evaluate(context)
        if isinstance(left, numbers.Number) and not isinstance(right, numbers.Number):
            right = float(right)
        if not isinstance(left, numbers.Number) and isinstance(right, numbers.Number):
            left = float(left)
        result = self.compareFun(left, right)
        context.debug.append("%s %s %s => %s" % (left, self.opStr, right, result))
        return result
    def __str__(self):
        return "ComparisonExpr(" + str(self.leftExpr) + ", " + str(self.rightExpr) + ", " + self.opStr + ")"
    def ast(self, indent = ""):
        inner_indent = indent + "  "
        return (
            indent + "(" + self.opStr + "\n"
            + self.leftExpr.ast(inner_indent) + "\n"
            + self.rightExpr.ast(inner_indent) + "\n"
            + indent + ")"
        )

# criteria (a boolean expression that will the following syntax):
#   expression: '(' expression ')'
#   expression: expression 'and' expression
#   expression: expression 'or' expression
#   expression: term operator term
#   term: fieldname | literal | expression
#   expression: match(regex_pattern, fieldname) (returns boolean)
#   expression: search(regex_pattern, fieldname) (returns boolean)
#   expression: cidrmatch(cidr_string, fieldname) (returns boolean)
#   fieldname: a string without space | get(literal_string)
#   operator: '==' | '!=' | '>=' | '<=' | '>' | '<'
#   literal: literal_string, literal_number, literal_array, literal_set
#   literal_string: python-style string literal
#   literal_number: python-style number literal
#   regular_expression: python-style string literal
#   literal_array: python style array literals
#   literal_set: set(literal_array)
class CriteriaParser:

    def __init__(self):
        self.whitespace = regex(r'\s+', re.MULTILINE)
        self.comment = regex(r'#.*')
        self.ignore =  many((self.whitespace | self.comment))

        # setup mutually referencing parsers as dummy parser where the fn parameter is replaced afterwards
        self.paren_comparison = Parser(lambda x: x)
        self.comparison = Parser(lambda x: x)
        self.term = Parser(lambda x: x)

        number_int = self.lexeme(regex(r'\d+')).parsecmap(lambda s: LiteralExpr(int(s)))
        number_float = self.lexeme(regex(r'\d+\.\d+')).parsecmap(lambda s: LiteralExpr(float(s)))
        self.number = number_float | number_int

        def any_char_fn(text, index=0):
            if index < len(text):
                return Value.success(index + 1, text[index])
            else:
                return Value.failure(index, 'any_char')
        any_char = Parser(any_char_fn)
        shortstringchar_double = none_of('"\n\\')
        shortstringchar_single = none_of("'\n\\")
        escapeseq = string('\\') >> any_char
        shortstringitem_single = shortstringchar_single | escapeseq.parsecmap(self.unescape)
        shortstring_single = (string("'") >> many(shortstringitem_single)) << string("'")
        shortstringitem_double = shortstringchar_double | escapeseq.parsecmap(self.unescape)
        shortstring_double = (string('"') >> many(shortstringitem_double)) << string('"')
        self.shortstring = (shortstring_single ^ shortstring_double).parsecmap(lambda arr: LiteralExpr(''.join(arr)))

        raw_escapeseq = (string('\\') + any_char).parsecmap(lambda x: x[0] + x[1])
        raw_shortstringitem_single = shortstringchar_single | raw_escapeseq
        raw_shortstring_single = (string("r'") >> many(raw_shortstringitem_single)) << string("'")
        raw_shortstringitem_double = shortstringchar_double | raw_escapeseq
        raw_shortstring_double = (string('r"') >> many(raw_shortstringitem_double)) << string('"')
        self.raw_shortstring = (raw_shortstring_single ^ raw_shortstring_double).parsecmap(
            lambda arr: LiteralExpr(''.join(arr))
        )

        self.literal = self.raw_shortstring ^ self.number ^ self.shortstring

        self.fieldname = regex("[A-Z_a-z][0-9A-Za-z_-]*").parsecmap(lambda s: FieldExpr(LiteralExpr(s)))
        self.fieldgetter = (
            self.lexeme(string('get')) >> self.lexeme(string('('))
            >> self.lexeme(self.literal)
            << self.lexeme(string(')'))
        ).parsecmap(lambda literalExpr: FieldExpr(literalExpr))

        self.arrayexpr = (
            self.lexeme(string('['))
            >> sepBy(self.term, self.lexeme(string(','))) << self.lexeme(string(']'))
        ).parsecmap(lambda arrExpr: ArrayExpr(arrExpr))

        self.setexpr = (
            self.lexeme(string('set')) >> self.lexeme(string('('))
            >> self.lexeme(self.term)
            << self.lexeme(string(')'))
        ).parsecmap(lambda expr: SetExpr(expr))

        self.term.fn = self.lexeme(self.literal ^ self.fieldgetter ^ self.setexpr ^ self.fieldname ^ self.arrayexpr)

        function_name = self.lexeme(string('search') ^ string('match') ^ string('cidrmatch'))
        function_call_args = separated(self.term, self.lexeme(string(',')), mint=2, maxt=2, end=None)
        self.function_call = ((function_name << self.lexeme(string('(')))
                + (function_call_args << self.lexeme(string(')')))).parsecmap(
            lambda x: MatchExpr(x[0], x[1][0], x[1][1])
        )

        op_equal = ((self.term << self.lexeme(string("=="))) + self.term).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], "==", lambda x, y: x == y)
        )
        op_not_equal = ((self.term << self.lexeme(string("!="))) + self.term).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], "!=", lambda x, y: x != y)
        )
        op_gt = ((self.term << self.lexeme(string(">"))) + self.term).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], ">", lambda x, y: x > y)
        )
        op_ge = ((self.term << self.lexeme(string(">="))) + self.term).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], ">=", lambda x, y: x >= y)
        )
        op_lt = ((self.term << self.lexeme(string("<"))) + self.term).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], "<", lambda x, y: x < y)
        )
        op_le = ((self.term << self.lexeme(string("<="))) + self.term).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], "<=", lambda x, y: x <= y)
        )
        self.comparison.fn = (
            op_equal ^ op_not_equal ^ op_ge ^ op_le ^ op_gt ^ op_lt ^ self.paren_comparison ^ self.function_call
        )

        self.conjunction = ((self.comparison << self.lexeme(string("and"))) + self.comparison).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], "and", lambda x, y: x and y)
        ) ^ self.comparison

        self.disjunction = ((self.conjunction << self.lexeme(string("or"))) + self.conjunction).parsecmap(
            lambda t: ComparisonExpr(t[0], t[1], "or", lambda x, y: x or y)
        ) ^ self.conjunction

        self.paren_comparison.fn = (self.lexeme(string('(')) >> self.disjunction) << self.lexeme(string(')'))

        self.expression = self.ignore >> self.disjunction

    def unescape(self, c):
        if c == '\n':
            return ''
        elif c == 'a':
            return '\a'
        elif c == 'b':
            return '\b'
        elif c == 'f':
            return '\f'
        elif c == 'n':
            return '\n'
        elif c == 'r':
            return '\r'
        elif c == 't':
            return '\t'
        elif c == 'v':
            return '\v'
        elif c == '\\':
            return '\\'
        else:
            return '\\' + c

    # lexer for words, skip all ignored characters.
    def lexeme(self, p):
        return p << self.ignore

    def parse(self, criteria):
        return self.expression.parse_strict(criteria)

    def test(self, parser, s):
        result = parser.parse_strict(s)
        print result

    def test_eval(self, criteria, record, expected, debug=False):
        expr = self.expression.parse_strict(criteria)
        c = Context(record)
        v = expr.evaluate(c)
        #print "criteria: %s => %s" % (criteria, "\n" + expr.ast())
        if v != expected or debug:
            print "ERROR: %s evaluated on %s => got %s expected %s" % (expr, c.record, v, expected)
            print "DEBUG: %s" % str(c.debug)

    def test_string(self, text_to_parse, expected_string):
        p = self.literal.parse_strict(text_to_parse)
        if type(p.value) == str and p.value == expected_string:
            print 'STR: SUCCESS on %s' % text_to_parse
        else:
            print 'STR: FAIL    on %s expected %s, got %s' % (text_to_parse, expected_string, p.value)

def main():
    print 'test_parsec'
    cp = CriteriaParser()
    cp.test_string("'abc'", "abc")
    cp.test_string("'ab\\tc'", "ab\tc")
    cp.test_string('"ab\\\\c"', "ab\\c")
    cp.test_string("r'abc'", "abc")
    cp.test_string("r'ab\\tc'", "ab\\tc")
    cp.test_string('r"ab\\\\c"', "ab\\\\c")
    cp.test(cp.term, '123')
    cp.test(cp.term, '3.14')
    cp.test(cp.term, '[1, 2]')
    cp.test(cp.term, 'set(["a", "b"])')
    cp.test(cp.term, 'set(get("users"))')
    cp.test(cp.function_call, 'search("pattern", "foo")')
    cp.test_eval('user == "admin"', {'user': "admin"}, True)
    cp.test_eval('user == "admin1"', {'user': "admin"}, False)
    cp.test_eval('get("user") == "admin"', {'user': "admin"}, True)
    cp.test_eval('get("field with spaces") == "admin"', {'field with spaces': "admin"}, True)
    cp.test_eval('count > 10', {'count': "15"}, True)
    cp.test_eval('count > 10', {'count': "5"}, False)
    cp.test_eval('count >= 10', {'count': "10"}, True)
    cp.test_eval('count >= 10', {'count': "9"}, False)
    cp.test_eval('count <= 10', {'count': "10"}, True)
    cp.test_eval('count <= 10', {'count': "11"}, False)
    cp.test_eval('count != 10', {'count': "11"}, True)
    cp.test_eval('count != 10', {'count': "10"}, False)
    cp.test_eval('  1 == 1 and 2 == 2', {}, True)
    cp.test_eval('1 == 1 and 2 == 2', {}, True)
    cp.test_eval('1 == 1 and 2 == 3', {}, False)
    cp.test_eval('1 == 1 and 2 == 2 or "foo" == "foo"', {}, True)
    cp.test_eval('1 == 1 and 2 != 2 or "foo" == "foo"', {}, True)
    cp.test_eval('1 == 1 and 2 != 2 or "foo" == "bar"', {}, False)
    cp.test_eval('1 == 1 and 2 != 2 or "foo" == "bar"', {}, False)
    cp.test_eval('1 == 1 and (2 != 2 or "foo" == "foo")', {}, True)
    cp.test_eval('[1, 2] == [1, 2]', {}, True)
    cp.test_eval('[1, 2] == [1, 3]', {}, False)
    cp.test_eval('set([1, 2]) == set([2, 1, 1])', {}, True)
    cp.test_eval('match("fo+", "foo")', {}, True)
    cp.test_eval('match("fo+", "bar")', {}, False)
    cp.test_eval('match("admin*", user)', {'user': "admin1"}, True)
    cp.test_eval('match("admin*", user)', {'user': "user"}, False)
    cp.test_eval('match("admin*", user) and count > 10', {'user': "admin1", "count": 15}, True)
    cp.test_eval(r'r"192\.168" == "192\\.168"', {}, True)
    cp.test_eval(r'match(r"192\.168\.\d+\.\d+", clientip)', {'clientip': "192.168.1.1"}, True)
    cp.test_eval(r'match(r"10\.10\.\d+\.\d+", clientip)', {'clientip': "192.168.1.1"}, False)
    cp.test_eval('cidrmatch("192.168.1.1/32", clientip)', {'clientip': "192.168.1.1"}, True)
    cp.test_eval('cidrmatch("192.168.1.1/32", clientip)', {'clientip': "192.168.1.2"}, False)
    cp.test_eval('cidrmatch("192.168.1.1/31", clientip)', {'clientip': "192.168.1.1"}, True)
    cp.test_eval('cidrmatch("192.168.1.1/0", clientip)', {'clientip': "1.2.3.4"}, True)
    cp.test_eval('cidrmatch("10.0.0.0/8", clientip)', {'clientip': "10.10.20.30"}, True)
    cp.test_eval('cidrmatch("10.0.0.0/8", clientip)', {'clientip': "11.10.20.30"}, False)
    cp.test_eval('set(get("users")) <= set(["admin1", "admin2"])', {'users': ['admin1', 'admin2']}, True)
    cp.test_eval('set(get("users")) <= set(["admin1", "admin2"])', {'users': ['admin1', 'admin3']}, False)

if __name__ == "__main__":
    main()

