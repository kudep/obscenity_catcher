#!/usr/bin/python3
# -*- coding: utf-8 -*-

import pymorphy2
import json
import re
import os
import sys
root_directory = os.path.dirname(os.path.realpath(__file__))
PATTERN_1 = r''.join((
    r'\w{0,5}[хx]([хx\s\!@#\$%\^&*+-\|\/]{0,6})',
    r'[уy]([уy\s\!@#\$%\^&*+-\|\/]{0,6})[ёiлeеюийя]\w{0,7}|\w{0,6}[пp]',
    r'([пp\s\!@#\$%\^&*+-\|\/]{0,6})[iие]([iие\s\!@#\$%\^&*+-\|\/]{0,6})',
    r'[3зс]([3зс\s\!@#\$%\^&*+-\|\/]{0,6})[дd]\w{0,10}|[сcs][уy]',
    r'([уy\!@#\$%\^&*+-\|\/]{0,6})[4чkк]\w{1,3}|\w{0,4}[bб]',
    r'([bб\s\!@#\$%\^&*+-\|\/]{0,6})[lл]([lл\s\!@#\$%\^&*+-\|\/]{0,6})',
    r'[yя]\w{0,10}|\w{0,8}[её][bб][лске@eыиаa][наи@йвл]\w{0,8}|\w{0,4}[еe]',
    r'([еe\s\!@#\$%\^&*+-\|\/]{0,6})[бb]([бb\s\!@#\$%\^&*+-\|\/]{0,6})',
    r'[uу]([uу\s\!@#\$%\^&*+-\|\/]{0,6})[н4ч]\w{0,4}|\w{0,4}[еeё]',
    r'([еeё\s\!@#\$%\^&*+-\|\/]{0,6})[бb]([бb\s\!@#\$%\^&*+-\|\/]{0,6})',
    r'[нn]([нn\s\!@#\$%\^&*+-\|\/]{0,6})[уy]\w{0,4}|\w{0,4}[еe]',
    r'([еe\s\!@#\$%\^&*+-\|\/]{0,6})[бb]([бb\s\!@#\$%\^&*+-\|\/]{0,6})',
    r'[оoаa@]([оoаa@\s\!@#\$%\^&*+-\|\/]{0,6})[тnнt]\w{0,4}|\w{0,10}[ё]',
    r'([ё\!@#\$%\^&*+-\|\/]{0,6})[б]\w{0,6}|\w{0,4}[pп]',
    r'([pп\s\!@#\$%\^&*+-\|\/]{0,6})[иeеi]([иeеi\s\!@#\$%\^&*+-\|\/]{0,6})',
    r'[дd]([дd\s\!@#\$%\^&*+-\|\/]{0,6})[oоаa@еeиi]',
    r'([oоаa@еeиi\s\!@#\$%\^&*+-\|\/]{0,6})[рr]\w{0,12}',
))

PATTERN_2 = r'|'.join((
    r"(\b[сs]{1}[сsц]{0,1}[uуy](?:[ч4]{0,1}[иаakк][^ц])\w*\b)",
    r"(\b(?!пло|стра|[тл]и)(\w(?!(у|пло)))*[хx][уy](й|йа|[еeё]|и|я|ли|ю)(?!га)\w*\b)",
    r"(\b(п[oо]|[нз][аa])*[хx][eе][рp]\w*\b)",
    r"(\b[мm][уy][дd]([аa][кk]|[oо]|и)\w*\b)",
    r"(\b\w*д[рp](?:[oо][ч4]|[аa][ч4])(?!л)\w*\b)",
    r"(\b(?!(?:кило)?[тм]ет)(?!смо)[а-яa-z]*(?<!с)т[рp][аa][хx]\w*\b)",
    r"(\b[к|k][аaoо][з3z]+[eе]?ё?л\w*\b)",
    r"(\b(?!со)\w*п[еeё]р[нд](и|иc|ы|у|н|е|ы)\w*\b)",
    r"(\b\w*[бп][ссз]д\w+\b)",
    r"(\b([нnп][аa]?[оo]?[xх])\b)",
    r"(\b([аa]?[оo]?[нnпбз][аa]?[оo]?)?([cс][pр][аa][^зжбсвм])\w*\b)",
    r"(\b\w*([оo]т|вы|[рp]и|[оo]|и|[уy]){0,1}([пnрp][iиеeё]{0,1}[3zзсcs][дd])\w*\b)",
    r"(\b(вы)?у?[еeё]?би?ля[дт]?[юоo]?\w*\b)",
    r"(\b(?!вело|ски|эн)\w*[пpp][eеиi][дd][oaоаеeирp](?![цянгюсмйчв])[рp]?(?![лт])\w*\b)",
    r"(\b(?!в?[ст]{1,2}еб)(?:(?:в?[сcз3о][тяaа]?[ьъ]?|вы|п[рp][иоo]|[уy]|р[aа][з3z][ьъ]?|к[оo]н[оo])?[её]б[а-яa-z]*)|(?:[а-яa-z]*[^хлрдв][еeё]б)\b)",
    r"(\b[з3z][аaоo]л[уy]п[аaeеин]\w*\b)",
))

regexp = re.compile(PATTERN_1, re.U | re.I)
regexp2 = re.compile(PATTERN_2, re.U | re.I)

morph = pymorphy2.MorphAnalyzer()

obscenity_words = set(json.load(
    open(os.path.join(root_directory, 'obscenity_dataset/obscenity_words.json'), encoding="utf-8")))
obscenity_words_extended = set(json.load(
    open(os.path.join(root_directory, 'obscenity_dataset/obscenity_words_extended.json'), encoding="utf-8")))
obscenity_words_exception = set(json.load(
    open(os.path.join(root_directory, 'obscenity_dataset/obscenity_words_exception.json'), encoding="utf-8")))
obscenity_words.update(obscenity_words_extended)
word_pattern = re.compile(r'[А-яЁё]+')


def check_obscenity(text):
    for word in word_pattern.findall(text):
        if len(word) < 3:
            continue
        word = word.lower()
        word.replace('ё', 'е')
        normal_word = morph.parse(word)[0].normal_form
        if normal_word in obscenity_words_exception\
                or word in obscenity_words_exception:
            continue
        if normal_word in obscenity_words\
                or word in obscenity_words\
                or bool(regexp.findall(normal_word))\
                or bool(regexp.findall(word))\
                or bool(regexp2.findall(normal_word))\
                or bool(regexp2.findall(word)):
            return True
    return False
