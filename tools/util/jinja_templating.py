"""
Creates a default jinja environment for tex-templates
"""
import os
import jinja2


def get_jinja_env():
    """ Get the default jinja environment"""

    templates = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")

    env = jinja2.Environment(
        block_start_string=r'\BLOCK{',
        block_end_string='}',
        variable_start_string=r'\VAR{',
        variable_end_string='}',
        comment_start_string=r'\#{',
        comment_end_string='}',
        line_statement_prefix='%%',
        line_comment_prefix='%#',
        trim_blocks=True,
        autoescape=False,
        loader=jinja2.FileSystemLoader(templates)
        )
    return env
