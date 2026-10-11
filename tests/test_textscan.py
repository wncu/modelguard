import unittest

from modelguard.textscan import check_python, check_template

LEGIT_TEMPLATE = (
    "{%- for message in messages %}{%- if message['role'] == 'system' %}{{ '<|im_start|>system\\n' + "
    "message['content'] + '<|im_end|>\\n' }}{%- endif %}{%- endfor %}{%- set ns = namespace(found=false) %}"
    "{%- if add_generation_prompt %}{{ '<|im_start|>assistant\\n' }}{%- endif %}{{ raise_exception('x') }}"
)


class TemplateTests(unittest.TestCase):
    def test_legit_template_clean(self):
        self.assertEqual(check_template(LEGIT_TEMPLATE), [])
        self.assertEqual(check_template('Describe yourself. You are self-aware.'), [])

    def test_ssti_payloads_high(self):
        payloads = [
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
            "{{ x|attr('\\x5f\\x5fclass\\x5f\\x5f') }}",
            "{{ lipsum.__globals__['os'] }}",
            "{{ self._TemplateReference__context }}",
        ]
        for p in payloads:
            self.assertIn('high', {sev for sev, _ in check_template(p)}, p)

    def test_review_signals(self):
        self.assertEqual(check_template("{{ x|attr('y') }}"), [('review', 'attr() filter')])


class PythonTests(unittest.TestCase):
    def test_clean_modeling_code(self):
        src = b'import torch\nfrom torch import nn\nclass M(nn.Module):\n    def forward(self, x):\n        return x\n'
        self.assertIsNone(check_python(src))

    def test_obfuscated_dropper_high(self):
        src = b'import base64\nexec(base64.b64decode("cHJpbnQoMSk="))\n'
        sev, summary = check_python(src)
        self.assertEqual(sev, 'high')
        self.assertIn('dynamic code execution', summary)

    def test_aliases_and_process_plus_network(self):
        src = b'import subprocess as sp\nimport requests\nsp.run(["id"])\nrequests.get("http://x")\n'
        self.assertEqual(check_python(src)[0], 'high')
        src = b'from os import system as s\ns("id")\n'
        self.assertEqual(check_python(src)[0], 'review')

    def test_unparseable(self):
        self.assertEqual(check_python(b'def (:\n')[0], 'review')


if __name__ == '__main__':
    unittest.main()
