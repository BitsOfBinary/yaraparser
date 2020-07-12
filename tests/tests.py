import unittest

from yaraparser import ParsedYaraRule, ParsedYaraTags, ParsedYaraImports, ParsedYaraMeta, ParsedYaraCondition


class TestParsedYaraRule(unittest.TestCase):
    def setUp(self):
        self.raw_rule = 'import "pe"\r\nimport "math"\r\n\r\nrule test_rule : tag1 tag2 {\r\n\tmeta:\r\n\t\tdescription = "Rule for testing the yaraparser"\r\n\t\tpower_level = 9001 //it\'s over\r\n\t\tbool_test = true\r\n\t\t\r\n\tstrings:\r\n\t\t// start strings\r\n\t\t$ = "anon string"\r\n\t\t$text = "named string"\r\n\t\t// ambiguous comment\r\n\t\t$text_w_modifiers = "named string with modifiers" ascii wide\r\n\t\t\r\n\t\t$hex = {AA BB CC DD}\r\n\t\t$regex = /test[0-9]{2}/\r\n\t\t\r\n\t\t// final comment\r\n\t\t\r\n\tcondition:\r\n\t\tuint16(0) == 0x5A4D and\r\n\t\tany of them\r\n}'
        self.parsed_yara_rule = ParsedYaraRule(self.raw_rule)

    def test_parsed_yara_rule_init(self):
        self.assertEqual(self.parsed_yara_rule.raw_rule, self.raw_rule)

    def test_carve_yara_tags(self):
        self.parsed_yara_rule.carve_yara_tags()
        self.assertEqual(self.parsed_yara_rule.tags.carved_tags, " tag1 tag2 ")

    def test_carve_yara_imports(self):
        self.parsed_yara_rule.carve_yara_imports()
        self.assertEqual(self.parsed_yara_rule.imports.carved_imports, 'import "pe"\r\nimport "math"\r\n\r\n')

    def test_parse_rule_name(self):
        self.parsed_yara_rule.parse_rule_name()
        self.assertEqual(self.parsed_yara_rule.rule_name, "test_rule")

    def test_carve_meta(self):
        self.parsed_yara_rule.carve_yara_meta()
        self.assertEqual(self.parsed_yara_rule.meta.carved_meta, '\t\tdescription = "Rule for testing the yaraparser"\r\n\t\tpower_level = 9001 //it\'s over\r\n\t\tbool_test = true\r\n\t\t\r')

    def test_carve_strings(self):
        self.parsed_yara_rule.carve_yara_strings()
        self.assertEqual(self.parsed_yara_rule.strings.carved_strings, '\t\t// start strings\r\n\t\t$ = "anon string"\r\n\t\t$text = "named string"\r\n\t\t// ambiguous comment\r\n\t\t$text_w_modifiers = "named string with modifiers" ascii wide\r\n\t\t\r\n\t\t$hex = {AA BB CC DD}\r\n\t\t$regex = /test[0-9]{2}/\r\n\t\t\r\n\t\t// final comment\r\n\t\t\r')

    def test_carve_condition(self):
        self.parsed_yara_rule.carve_yara_condition()
        self.assertEqual(self.parsed_yara_rule.condition.carved_condition, '\t\tuint16(0) == 0x5A4D and\r\n\t\tany of them\r')


class TestParsedYaraTags(unittest.TestCase):
    def setUp(self):
        self.parsed_yara_tags = ParsedYaraTags()
        self.parsed_yara_tags.carved_tags = " tag1 tag2 "

    def test_parse_yara_tags(self):
        self.parsed_yara_tags.parse_yara_tags()
        self.assertEqual(self.parsed_yara_tags.tags, ["tag1", "tag2"])


class TestParsedYaraImports(unittest.TestCase):
    def setUp(self):
        self.parsed_yara_imports = ParsedYaraImports()
        self.parsed_yara_imports.carved_imports = 'import "pe"\r\nimport "math"\r\n\r\n'

    def test_parse_yara_imports(self):
        self.parsed_yara_imports.parse_yara_imports()
        self.assertEqual(self.parsed_yara_imports.imports, ["pe", "math"])


class TestParsedYaraMeta(unittest.TestCase):
    def setUp(self):
        self.parsed_yara_meta = ParsedYaraMeta()
        self.parsed_yara_meta.carved_meta = '\t\tdescription = "Rule for testing the yaraparser"\r\n\t\tpower_level = 9001 //it\'s over\r\n\t\tbool_test = true\r\n\t\t\r'

    def test_parse_yara_meta_str(self):
        self.parsed_yara_meta.parse_yara_meta()
        self.assertEqual(self.parsed_yara_meta.meta["description"][0].value, "Rule for testing the yaraparser")
        self.assertEqual(self.parsed_yara_meta.meta["description"][0].meta_type, "text")

    def test_parse_yara_meta_int(self):
        self.parsed_yara_meta.parse_yara_meta()
        self.assertEqual(self.parsed_yara_meta.meta["power_level"][0].value, 9001)
        self.assertEqual(self.parsed_yara_meta.meta["power_level"][0].meta_type, "int")

    def test_parse_yara_meta_bool(self):
        self.parsed_yara_meta.parse_yara_meta()
        self.assertEqual(self.parsed_yara_meta.meta["bool_test"][0].value, True)
        self.assertEqual(self.parsed_yara_meta.meta["bool_test"][0].meta_type, "bool")

    def test_parse_yara_meta_comment(self):
        self.parsed_yara_meta.parse_yara_meta()
        self.assertEqual(self.parsed_yara_meta.meta["power_level"][0].yara_comment.inline, "it's over")


class TestParsedYaraCondition(unittest.TestCase):
    def setUp(self):
        self.parsed_yara_condition = ParsedYaraCondition()
        self.parsed_yara_condition.carved_condition = '\t\tuint16(0) == 0x5A4D and\r\n\t\tany of them\r'

    def test_parse_yara_condition(self):
        self.parsed_yara_condition.parse_yara_condition()
        self.assertEqual(self.parsed_yara_condition.raw_condition, 'uint16(0) == 0x5A4D and any of them')