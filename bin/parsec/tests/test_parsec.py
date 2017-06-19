#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import generators

'''
Test the basic functions of parsec.py.
'''

__author__ = 'He Tao, sighingnow@gmail.com'

import random
import unittest

from parsec import *

class ParsecTest(unittest.TestCase):
    '''Test the implementation of Text.Parsec. (The final test for all apis)'''
    def test_times_with_then(self):
        parser = times(letter(), 3) >> digit()
        self.assertEqual(parser.parse('xyz1'), '1')
        self.assertRaises(ParseError, parser.parse, 'xy1')
        self.assertRaises(ParseError, parser.parse, 'xyz')
        self.assertRaises(ParseError, parser.parse, 'xyzw')

    def test_many_with_then(self):
        parser = many(string('x')) >> string('y')
        self.assertEqual(parser.parse('y'), 'y')
        self.assertEqual(parser.parse('xy'), 'y')
        self.assertEqual(parser.parse('xxxxxy'), 'y')

    def test_times_with_min_and_max(self):
        parser = times(letter(), 2, 4)
        self.assertEqual(parser.parse('xy'), ['x', 'y'])
        self.assertEqual(parser.parse('xyz'), ['x', 'y', 'z'])
        self.assertEqual(parser.parse('xyzw'), ['x', 'y', 'z', 'w'])
        self.assertEqual(parser.parse('xyzwv'), ['x', 'y', 'z', 'w'])
        self.assertRaises(ParseError, parser.parse, 'x')

    def test_times_with_min_and_max_and_then(self):
        parser = times(letter(), 2, 4) >> digit()
        self.assertEqual(parser.parse('xy1'), '1')
        self.assertEqual(parser.parse('xyz1'), '1')
        self.assertEqual(parser.parse('xyzw1'), '1')
        self.assertRaises(ParseError, parser.parse, 'xy')
        self.assertRaises(ParseError, parser.parse, 'xyzw')
        self.assertRaises(ParseError, parser.parse, 'xyzwv1')
        self.assertRaises(ParseError, parser.parse, 'x1')

class ParsecPrimTest(unittest.TestCase):
    '''Test the implementation of Text.Parsec.Prim.'''

    def test_bind(self):
        nonlocals = {'piped': None}

        def binder(x):
            nonlocals['piped'] = x
            return string('y')

        parser = string('x').bind(binder)
        self.assertEqual(parser.parse('xy'), 'y')
        self.assertEqual(nonlocals['piped'], 'x')
        self.assertRaises(ParseError, parser.parse, 'x')

    def test_compose(self):
        parser = string('x') >> string('y')
        self.assertEqual(parser.parse('xy'), 'y')
        self.assertRaises(ParseError, parser.parse, 'y')
        self.assertRaises(ParseError, parser.parse, 'z')

    def test_joint(self):
        parser = string('x') + string('y')
        self.assertEqual(parser.parse('xy'), ('x', 'y'))
        self.assertRaises(ParseError, parser.parse, 'y')
        self.assertRaises(ParseError, parser.parse, 'z')

    def test_choice(self):
        parser = string('x') | string('y')
        self.assertEqual(parser.parse('x'), 'x')
        self.assertEqual(parser.parse('y'), 'y')
        self.assertRaises(ParseError, parser.parse, 'z')

        parser = string('xy') | string('xz')
        self.assertEqual(parser.parse('xy'), 'xy')
        self.assertRaises(ParseError, parser.parse, 'xz')

    def test_try_choice(self):
        parser = string('x') ^ string('y')
        self.assertEqual(parser.parse('x'), 'x')
        self.assertEqual(parser.parse('y'), 'y')
        self.assertRaises(ParseError, parser.parse, 'z')

        parser = string('xy') ^ string('xz')
        self.assertEqual(parser.parse('xy'), 'xy')
        self.assertEqual(parser.parse('xz'), 'xz')

    def test_ends_with(self):
        parser = string('x') < string('y')
        self.assertEqual(parser.parse('xy'), 'x')
        self.assertRaises(ParseError, parser.parse, 'xx')

    def test_parsecmap(self):

        def mapfn(p):
            return p+p

        parser = string('x').parsecmap(mapfn)
        self.assertEqual(parser.parse('x'), 'xx')

    def test_desc(self):
        parser = string('x')
        self.assertEqual(parser.parse('x'), 'x')
        self.assertRaises(ParseError, parser.parse, 'y')

    def test_mark(self):
        parser = many(mark(many(letter())) << string("\n"))

        lines = parser.parse("asdf\nqwer\n")

        self.assertEqual(len(lines), 2)

        (start, letters, end) = lines[0]
        self.assertEqual(start, (0, 0))
        self.assertEqual(letters, ['a', 's', 'd', 'f'])
        self.assertEqual(end, (0, 4))

        (start, letters, end) = lines[1]
        self.assertEqual(start, (1, 0))
        self.assertEqual(letters, ['q', 'w', 'e', 'r'])
        self.assertEqual(end, (1, 4))

    def test_choice_with_compose(self):
        parser = (string('\\') >> string('y')) | string('z')
        self.assertEqual(parser.parse('\\y'), 'y')
        self.assertEqual(parser.parse('z'), 'z')
        self.assertRaises(ParseError, parser.parse, '\\z')

class ParsecCombinatorTest(unittest.TestCase):
    '''Test the implementation of Text.Parsec.Combinator.'''
    def test_times(self):
        parser = times(string('x'), 2, 10)
        self.assertEqual(parser.parse('xxx'), ['x', 'x', 'x'])
        self.assertRaises(ParseError, parser.parse, 'x')
        self.assertRaises(ParseError, parser.parse, 'xyyyyyyyyyyyyyyyyyyyyyy')

        parser = times(letter(), 0)
        self.assertEqual(parser.parse(''), [])
        self.assertEqual(parser.parse('x'), [])
        self.assertEqual(parser.parse('xxxxx'), [])

    def test_count(self):
        parser = count(letter(), 3)
        self.assertEqual(parser.parse('xyz'), ['x', 'y', 'z'])
        self.assertEqual(parser.parse('xyzwwwww'), ['x', 'y', 'z'])
        self.assertRaises(ParseError, parser.parse, 'xy')

    def test_many(self):
        parser = many(letter())
        self.assertEqual(parser.parse('x'), ['x'])
        self.assertEqual(parser.parse('xyz'), ['x', 'y', 'z'])
        self.assertEqual(parser.parse(''), [])
        self.assertEqual(parser.parse('1'), [])

    def test_many1(self):
        parser = many1(letter())
        self.assertEqual(parser.parse('x'), ['x'])
        self.assertEqual(parser.parse('xyz'), ['x', 'y', 'z'])
        self.assertRaises(ParseError, parser.parse, '')
        self.assertRaises(ParseError, parser.parse, '1')

    def test_separated(self):
        parser = separated(string('x'), string(','), 2, 4)
        self.assertEqual(parser.parse('x,x,x') , ['x', 'x', 'x'])
        self.assertEqual(parser.parse('x,x,x,'), ['x', 'x', 'x'])
        self.assertRaises(ParseError, parser.parse, 'x')
        self.assertRaises(ParseError, parser.parse, 'x,')
        self.assertRaises(ParseError, parser.parse, 'x,y,y,y,y')
        self.assertRaises(ParseError, parser.parse, 'x,y,y,y,y,')
        self.assertEqual(parser.parse('x,x,y,y' ), ['x','x'])
        self.assertEqual(parser.parse('x,x,y,y,'), ['x','x'])

        parser = separated(letter(), string(','), 0)
        self.assertEqual(parser.parse('')          , [])
        self.assertEqual(parser.parse('x')         , [])
        self.assertEqual(parser.parse('x,')        , [])
        self.assertEqual(parser.parse('x,x,x,x,x') , [])
        self.assertEqual(parser.parse('x,x,x,x,x,'), [])

    def test_sepBy(self):
        parser = sepBy(letter(), string(','))
        self.assertEqual(parser.parse_strict('x')     , ['x'])
        self.assertEqual(parser.parse       ('x,')    , ['x'])
        self.assertEqual(parser.parse_strict('x,y,z') , ['x', 'y', 'z'])
        self.assertEqual(parser.parse       ('x,y,z,'), ['x', 'y', 'z'])
        self.assertEqual(parser.parse       ('') , [])  # nothing consumed
        self.assertEqual(parser.parse       ('1'), [])  # nothing consumed
        self.assertEqual(parser.parse       ('1,'), []) # nothing consumed

    def test_sepBy1(self):
        parser = sepBy1(letter(), string(','))
        self.assertEqual(parser.parse_strict('x')     , ['x'])
        self.assertEqual(parser.parse       ('x,')    , ['x'])
        self.assertEqual(parser.parse_strict('x,y,z') , ['x', 'y', 'z'])
        self.assertEqual(parser.parse       ('x,y,z,'), ['x', 'y', 'z'])
        self.assertRaises(ParseError, parser.parse, (''))
        self.assertRaises(ParseError, parser.parse, ('1'))
        self.assertRaises(ParseError, parser.parse, ('1,'))

    def test_endBy(self):
        parser = endBy(letter(), string(','))
        self.assertRaises(ParseError, parser.parse, ('x'))
        self.assertRaises(ParseError, parser.parse, ('x,y,z'))
        self.assertEqual(parser.parse_strict('x,')    , ['x'])
        self.assertEqual(parser.parse_strict('x,y,z,'), ['x', 'y', 'z'])
        self.assertEqual(parser.parse       ('')      , [])
        self.assertEqual(parser.parse       ('1')     , [])
        self.assertEqual(parser.parse       ('1,')    , [])

    def test_endBy1(self):
        parser = endBy1(letter(), string(','))
        self.assertRaises(ParseError, parser.parse, ('x'))
        self.assertRaises(ParseError, parser.parse, ('x,y,z'))
        self.assertEqual(parser.parse_strict('x,')    , ['x'])
        self.assertEqual(parser.parse_strict('x,y,z,'), ['x', 'y', 'z'])
        self.assertRaises(ParseError, parser.parse, (''))
        self.assertRaises(ParseError, parser.parse, ('1'))
        self.assertRaises(ParseError, parser.parse, ('1,'))

    def test_sepEndBy(self):
        parser = sepEndBy(letter(), string(','))
        self.assertEqual(parser.parse_strict('x')     , ['x'])
        self.assertEqual(parser.parse_strict('x,')    , ['x'])
        self.assertEqual(parser.parse_strict('x,y,z') , ['x', 'y', 'z'])
        self.assertEqual(parser.parse_strict('x,y,z,'), ['x', 'y', 'z'])
        self.assertEqual(parser.parse       ('')      , [])
        self.assertEqual(parser.parse       ('1')     , [])
        self.assertEqual(parser.parse       ('1,')    , [])

    def test_sepEndBy1(self):
        parser = sepEndBy1(letter(), string(','))
        self.assertEqual(parser.parse_strict('x')     , ['x'])
        self.assertEqual(parser.parse_strict('x,')    , ['x'])
        self.assertEqual(parser.parse_strict('x,y,z') , ['x', 'y', 'z'])
        self.assertEqual(parser.parse_strict('x,y,z,'), ['x', 'y', 'z'])
        self.assertRaises(ParseError, parser.parse, (''))
        self.assertRaises(ParseError, parser.parse, ('1'))
        self.assertRaises(ParseError, parser.parse, ('1,'))

class ParsecCharTest(unittest.TestCase):
    '''Test the implementation of Text.Parsec.Char.'''

    def test_string(self):
        parser = string('x')
        self.assertEqual(parser.parse('x'), 'x')
        self.assertRaises(ParseError, parser.parse, 'y')

    def test_regex(self):
        parser = regex(r'[0-9]')
        self.assertEqual(parser.parse('1'), '1')
        self.assertEqual(parser.parse('4'), '4')
        self.assertRaises(ParseError, parser.parse, 'x')

class ParserGeneratorTest(unittest.TestCase):
    '''Test the implementation of Parser Generator.(generate)'''
    def test_generate_desc(self):
        description = 'expected description for fn'

        @generate(description)
        def fn():
            yield string('t')

        with self.assertRaises(ParseError) as err: fn.parse('x')

        ex = err.exception

        self.assertEqual(ex.expected, description)
        self.assertEqual(ex.text, 'x')
        self.assertEqual(ex.index, 0)

    def test_generate_backtracking(self):
        @generate
        def xy():
            yield string('x')
            yield string('y')
            assert False
        parser = xy | string('z')
        # should not finish executing xy()
        self.assertEqual(parser.parse('z'), 'z')

if __name__ == '__main__':
    unittest.main()
