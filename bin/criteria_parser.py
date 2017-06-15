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

class FieldExpr(Expr):
    def __init__(self, field):
        self.field = field
    def evaluate(self, context):
        if self.field in context.record:
            context.debug.append("record['%s'] => %s" % (self.field, context.record[self.field]))
            return context.record[self.field]
        else:
            context.debug.append("record['%s'] => None" % self.field)
            return None
    def __str__(self):
        return "FieldExpr(" + self.field + ")"
    def ast(self, indent = ""):
        return indent + "record['%s']" % self.field

class MatchExpr(Expr):
    def __init__(self, functionName, patternExpr, stringExpr):
        self.functionName = functionName
        self.patternExpr = patternExpr
        self.stringExpr = stringExpr
    def evaluate(self, context):
        import re
        pattern = self.patternExpr.evaluate(context)
        s = self.stringExpr.evaluate(context)
        if self.functionName == 'search':
            match_obj = re.search(pattern, s)
        elif self.functionName == 'match':
            match_obj = re.match(pattern, s)
        else:
            raise RuntimeError('invalid function name: %s' % self.functionName)
        context.debug.append("%s(%s, %s) => %s" % (self.functionName, pattern, s, str(match_obj)))
        return match_obj is not None
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

class CriteriaParser:

    def __init__(self):
        self.whitespace = regex(r'\s+', re.MULTILINE)
        self.comment = regex(r'#.*')
        self.ignore =  many((self.whitespace | self.comment))

        # setup mutually referencing parsers as dummy parser where the fn parameter is replaced afterwards
        self.paren_comparison = Parser(lambda x: x)
        self.comparison = Parser(lambda x: x)

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
        self.raw_shortstring = (raw_shortstring_single ^ raw_shortstring_double).parsecmap(lambda arr: LiteralExpr(''.join(arr)))

        self.literal = self.raw_shortstring ^ self.number ^ self.shortstring

        self.fieldname = regex("[A-Z_a-z][0-9A-Za-z_-]*").parsecmap(lambda s: FieldExpr(s))

        self.term = self.lexeme(self.literal ^ self.fieldname)

        function_name = self.lexeme(string('search')) ^ self.lexeme(string('match'))
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
        self.comparison.fn = op_equal ^ op_not_equal ^ op_ge ^ op_le ^ op_gt ^ op_lt ^ self.paren_comparison ^ self.function_call

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
    cp.test(cp.function_call, 'search("pattern", "foo")')
    cp.test_eval('user == "admin"', {'user': "admin"}, True)
    cp.test_eval('user == "admin1"', {'user': "admin"}, False)
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
    cp.test_eval('match("fo+", "foo")', {}, True)
    cp.test_eval('match("fo+", "bar")', {}, False)
    cp.test_eval('match("admin*", user)', {'user': "admin1"}, True)
    cp.test_eval('match("admin*", user)', {'user': "user"}, False)
    cp.test_eval('match("admin*", user) and count > 10', {'user': "admin1", "count": 15}, True)
    cp.test_eval(r'r"192\.168" == "192\\.168"', {}, True)
    cp.test_eval(r'match(r"192\.168\.\d+\.\d+", clientip)', {'clientip': "192.168.1.1"}, True)
    cp.test_eval(r'match(r"10\.10\.\d+\.\d+", clientip)', {'clientip': "192.168.1.1"}, False)

if __name__ == "__main__":
    main()

