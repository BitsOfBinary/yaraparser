yaraparser
===========

Python 3 tool to parse Yara rules (extension of yarabuilder)

NOTE: this is still in early development (lots of edge cases to work out still)

Installation
------------

yarabuilder requires Python 3+::

    python setup.py install
	
Usage
-----
Via the command line::

    $ yaraparser --help
    usage: yaraparser [-h] --file FILE

    Parse Yara rules into a dictionary or Python object

    optional arguments:
      -h, --help   show this help message and exit
      --file FILE  File containing Yara rules to parse

Via Python:
.. code-block:: python

    >>> import yaraparser
    >>>
    >>> rules = yaraparser.ParsedYaraRules()
    >>>
    >>> with open("test.yar", "r") as infile:
    ...     raw_rules = infile.read()
    ...
    >>> rules.parse_yara_rules(raw_rules)
    >>>
    >>> print(rules.get_yara_rules())