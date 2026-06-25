import click
from sentinelrecon.cli.commands.scan import scan

@click.group(name="sentinelrecon")
@click.version_option(version="1.0.0", prog_name="SentinelRecon")
@click.pass_context
def cli(ctx):
    """
    SentinelRecon - AI-Powered Intelligent Reconnaissance Toolkit
    
    Advanced network reconnaissance with AI-driven vulnerability analysis.
    """
    ctx.ensure_object(dict)

cli.add_command(scan)

# Other commands (history, config, report) can be added here later

if __name__ == '__main__':
    cli(obj={})
