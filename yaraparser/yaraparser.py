import yarabuilder
import re


class ParsedYaraImports(yarabuilder.YaraImports):

    def __init__(self):
        yarabuilder.YaraImports.__init__(self)
        self.carved_imports = ""

    def parse_yara_imports(self):
        for line in self.carved_imports.splitlines():
            if line.startswith("import"):
                parsed_import_regex = re.search("[\"'](.*)[\"']", line)

                if parsed_import_regex.group(1):
                    self.add_import(parsed_import_regex.group(1))


class ParsedYaraTags(yarabuilder.YaraTags):

    def __init__(self):
        yarabuilder.YaraTags.__init__(self)
        self.carved_tags = ""

    def parse_yara_tags(self):
        for tag in self.carved_tags.split(" "):
            if tag:
                self.add_tag(tag)


class ParsedYaraMeta(yarabuilder.YaraMeta):

    _parsed_meta_regex = re.compile(r"([a-zA-Z0-9_]{,128})\s*=\s*(.*)")
    _parsed_raw_meta_value_regex = re.compile(r"(.*)//(.*)")
    _text_str_parse_regex = re.compile(r"[\"'](.*)[\"']")
    _int_str_parse_regex = re.compile(r"(\d*)")
    _parsed_comment_regex = re.compile(r"//(.*)")

    def __init__(self):
        yarabuilder.YaraMeta.__init__(self)
        self.carved_meta = ""
        self.saved_comment = ""
        self.saved_meta_name = ""
        self.saved_meta_index = 0

    def parse_yara_meta(self):
        for line in self.carved_meta.splitlines():

            meta_value = None
            meta_type = None
            meta_comment = None

            # Look for a comment at the end of the line
            parsed_comment_matches = re.search(self._parsed_comment_regex, line)

            if bool(parsed_comment_matches):
                meta_comment = parsed_comment_matches.group(1)

            # Parse out the meta name and value
            parsed_meta_regex_matches = re.search(self._parsed_meta_regex, line)

            if bool(parsed_meta_regex_matches):

                meta_name = parsed_meta_regex_matches.group(1)
                raw_meta_value = parsed_meta_regex_matches.group(2)

                parsed_raw_meta_value_matches = re.search(self._parsed_raw_meta_value_regex, raw_meta_value)

                if bool(parsed_raw_meta_value_matches):
                    raw_meta_value = parsed_raw_meta_value_matches.group(1)
                    #meta_comment = parsed_raw_meta_value_matches.group(2)

                text_str_parse_matches = re.search(self._text_str_parse_regex, raw_meta_value)

                if bool(text_str_parse_matches):
                    meta_value = text_str_parse_matches.group(1)
                    meta_type = "text"

                else:
                    if "true" in raw_meta_value:
                        meta_value = True
                        meta_type = "bool"

                    elif "false" in raw_meta_value:
                        meta_value = False
                        meta_type = "bool"

                    else:
                        int_str_parse_matches = re.search(self._int_str_parse_regex, raw_meta_value)

                        if bool(int_str_parse_matches):
                            meta_value = int(int_str_parse_matches.group(1))
                            meta_type = "int"

                        else:
                            print("Unable to parse meta entry")

                # If successfully parsed, add the values to ParsedMeta
                if meta_name and meta_value and meta_type:
                    meta_entry_index = self.add_meta(meta_name, meta_value, meta_type=meta_type)

                    self.saved_meta_name = meta_name
                    self.saved_meta_index = meta_entry_index

                    if meta_comment:
                        self.meta[meta_name][meta_entry_index].add_comment(meta_comment)

                    if self.saved_comment:
                        self.meta[meta_name][meta_entry_index].add_comment(self.saved_comment, position="above")
                        self.saved_comment = None

                elif meta_comment:
                    self.saved_comment = meta_comment

        # After going through all lines, if there is a comment left, append it to the last entry
        if self.saved_comment:
            self.meta[self.saved_meta_name][self.saved_meta_index].add_comment(self.saved_comment, position="below")


class ParsedYaraStrings(yarabuilder.YaraStrings):

    _parsed_comment_regex = re.compile(r"//(.*)")
    _parsed_string_regex = re.compile(r"\$([a-zA-Z0-9_]{,128})\s*=\s*(.*)")

    def __init__(self):
        yarabuilder.YaraStrings.__init__(self)
        self.carved_strings = ""

    def parse_yara_strings(self):
        for line in self.carved_strings.splitlines():

            meta_comment = None
            string_to_add = False
            string_name = None
            string_value = None
            str_type = None

            # Look for a comment at the end of the line
            parsed_comment_matches = re.search(self._parsed_comment_regex, line)

            if bool(parsed_comment_matches):
                meta_comment = parsed_comment_matches.group(1)

            # Parse out the string name and value
            parsed_string_regex_matches = re.search(self._parsed_string_regex, line)

            if bool(parsed_string_regex_matches):

                string_name = parsed_string_regex_matches.group(1)
                raw_string_value = parsed_string_regex_matches.group(2)

                # TODO: handle case where there is a comment after the string
                if raw_string_value.startswith("\""):
                    string_value = raw_string_value[1:raw_string_value.rfind("\"")]
                    str_type = "text"
                    string_to_add = True

                elif raw_string_value.startswith("/"):
                    string_value = raw_string_value[1:raw_string_value.rfind("/")]
                    str_type = "regex"
                    string_to_add = True

                elif raw_string_value.startswith("{"):
                    string_value = raw_string_value[1:raw_string_value.rfind("}")]
                    str_type = "hex"
                    string_to_add = True

            if string_to_add:
                if string_name:
                    self.add_string(string_name, string_value, str_type=str_type)

                else:
                    string_name = self.add_anonymous_string(string_value, str_type=str_type)

                if meta_comment:
                    self.strings[string_name].add_comment(meta_comment)

                string_to_add = False


class ParsedYaraCondition(yarabuilder.YaraCondition):

    def __init__(self):
        yarabuilder.YaraCondition.__init__(self)
        self.carved_condition = ""

    def parse_yara_condition(self):

        conditions = self.carved_condition.strip().replace('\r', '').split('\n')

        raw_condition = conditions[0]

        if len(conditions) > 1:
            for condition in conditions[1:]:
                raw_condition = "%s %s" % (raw_condition, condition.strip())

        self.set_yara_condition(raw_condition)


class ParsedYaraRule(yarabuilder.YaraRule):

    _parsed_rule_name_regex = re.compile(r"rule ([a-zA-Z0-9_]{,128})")
    _carved_tags_regex = re.compile(r"rule [a-zA-Z0-9_]{,128}:(.*){")

    def __init__(self, raw_rule, whitespace="    "):
        yarabuilder.YaraRule.__init__(self, "", whitespace=whitespace)
        self.raw_rule = raw_rule
        self.imports = ParsedYaraImports()
        self.tags = ParsedYaraTags()
        self.meta = ParsedYaraMeta()
        self.strings = ParsedYaraStrings()
        self.condition = ParsedYaraCondition()

    def parse_rule_name(self):
        parsed_rule_name_matches = re.search(self._parsed_rule_name_regex, self.raw_rule)

        if parsed_rule_name_matches.group(1):
            self.rule_name = parsed_rule_name_matches.group(1)

    def carve_yara_imports(self):
        rule_identifier_index = self.raw_rule.find("rule ")

        self.imports.carved_imports = self.raw_rule[: rule_identifier_index]

    def carve_yara_tags(self):
        carved_tags_matches = re.search(self._carved_tags_regex, self.raw_rule)

        if carved_tags_matches and carved_tags_matches.group(1):
            self.tags.carved_tags = carved_tags_matches.group(1)

    def carve_yara_meta(self):
        # TODO: handle case where there is a comment after the meta tag
        if bool(re.search(r"\r?\n\s*strings:", self.raw_rule)):
            carved_meta_regex = re.search(r"meta:\s*\r?\n(.*)\r?\n\s*strings:", self.raw_rule, re.DOTALL)

        else:
            carved_meta_regex = re.search(r"meta:\s*\r?\n(.*)\r?\n\s*condition:", self.raw_rule, re.DOTALL)

        if carved_meta_regex and carved_meta_regex.group(1):
            self.meta.carved_meta = carved_meta_regex.group(1)

    def carve_yara_strings(self):
        # TODO: handle case where there is a comment after the meta tag
        carved_strings_regex = re.search(r"strings:\s*\r?\n(.*)\r?\n\s*condition:", self.raw_rule, re.DOTALL)

        if carved_strings_regex and carved_strings_regex.group(1):
            self.strings.carved_strings = carved_strings_regex.group(1)

    def carve_yara_condition(self):
        carved_condition_regex = re.search(r"condition:\s*\r?\n(.*)\r?\n\s*}", self.raw_rule, re.DOTALL)

        if carved_condition_regex.group(1):
            self.condition.carved_condition = carved_condition_regex.group(1)

    def parse_yara_rule(self):
        self.parse_rule_name()

        self.carve_yara_imports()
        if self.imports.carved_imports:
            self.imports.parse_yara_imports()

        self.carve_yara_tags()
        if self.tags.carved_tags:
            self.tags.parse_yara_tags()

        self.carve_yara_meta()
        if self.meta.carved_meta:
            self.meta.parse_yara_meta()

        self.carve_yara_strings()
        if self.strings.carved_strings:
            self.strings.parse_yara_strings()

        self.carve_yara_condition()
        self.condition.parse_yara_condition()

        # Clear the raw rule after parsing
        self.raw_rule = ""


class ParsedYaraRules(yarabuilder.YaraBuilder):

    #_rule_header_regex = re.compile(r"(?:import \".*\"\s*\n)*rule [a-zA-Z0-9_]{,128}\s*:?[A-Za-z0-9_\n\r\s]*{", re.DOTALL)
    _rule_header_regex = re.compile(r"(?:import \"\w{,20}\"\s{,128}\n)*rule [a-zA-Z0-9_]{,128}\s{,128}:?[A-Za-z0-9_\n\r\s]{,256}{", re.DOTALL)
    #_carved_condition_regex = re.compile(r"condition:\s*\r?\n.*\r?\n\s*}", re.DOTALL)
    _carved_condition_regex = re.compile(r"condition:\s*\r?\n", re.DOTALL | re.S)

    def __init__(self, whitespace="    ", logger=None):
        yarabuilder.YaraBuilder.__init__(self, whitespace=whitespace, logger=logger)

    def _find_end_of_rule(self, raw_rule):

        condition_header_matches = re.search(self._carved_condition_regex, raw_rule)

        if condition_header_matches:
            start_of_condition = condition_header_matches.start()
            end_of_rule = raw_rule[start_of_condition:].find("}") + start_of_condition + 1

            return end_of_rule

        else:
            return 0

    def parse_yara_rules(self, raw_rules):
        rule_header_regex_matches = re.finditer(self._rule_header_regex, raw_rules)

        for match in rule_header_regex_matches:
            start_of_rule = match.span()[0]
            start_of_rule_content = match.span()[1]
            end_of_rule = self._find_end_of_rule(raw_rules[start_of_rule_content:]) + start_of_rule + start_of_rule_content

            yara_rule = ParsedYaraRule(raw_rules[start_of_rule: end_of_rule], whitespace=self.whitespace)
            yara_rule.parse_yara_rule()

            self.yara_rules[yara_rule.rule_name] = yara_rule


def main():  # pragma: no cover
    #raw_rule = 'import "pe"\r\nimport "math"\r\n\r\nrule test_rule : tag1 tag2 {\r\n\tmeta:\r\n\t\tdescription = "Rule for testing the yaraparser"\r\n\t\tpower_level = 9001 //it\'s over\r\n\t\tbool_test = true\r\n\t\t\r\n\tstrings:\r\n\t\t// start strings\r\n\t\t$ = "anon string"\r\n\t\t$text = "named string"\r\n\t\t// ambiguous comment\r\n\t\t$text_w_modifiers = "named string with modifiers" ascii wide\r\n\t\t\r\n\t\t$hex = {AA BB CC DD}\r\n\t\t$regex = /test[0-9]{2}/\r\n\t\t\r\n\t\t// final comment\r\n\t\t\r\n\tcondition:\r\n\t\tuint16(0) == 0x5A4D and\r\n\t\tany of them\r\n}'

    #rule = ParsedYaraRule(raw_rule)
    #rule.parse_yara_rule()

    #print(rule.build_rule())

    with open("test.yar", "r") as infile:
        raw_rule = infile.read()

    rules = ParsedYaraRules()
    rules.parse_yara_rules(raw_rule)

    print(rules.build_rules())


if __name__ == "__main__":  # pragma: no cover
    main()
