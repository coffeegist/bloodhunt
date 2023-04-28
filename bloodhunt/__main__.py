from enum import Enum 
from pathlib import Path
import typer
from typing import List
from bloodhunt.logger import init_logger, logger, console
from bloodhunt import __version__
from bloodhunt.lib.hunter import Hunter


app = typer.Typer(
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)


class QuerySet(str, Enum):
    all = "all"
    summary = "summary"
    details = "details"
    escalation = "escalation"


@app.command(no_args_is_help=True, help='bloodhunt help!')
def main(
    host: str = typer.Option('neo4j://localhost', '--host', '-h', help='Neo4j Host'),
    username: str = typer.Option('neo4j', '--username', '-u', help='Neo4j Username'),
    password: str = typer.Option('neo4j', '--password', '-p', help='Neo4j Password'),
    querie_set: QuerySet = typer.Option(QuerySet.all, '--queries', '-q', help='Query set to be ran'),
    edge_filter: List[str] = typer.Option(None, '--edge-filter', '-e', help='Edges to ignore when searching paths. This can be specified multiple times.'),
    limit_results: str = typer.Option(None, '--limit-results', '-l', help='The limit of results to be returned by each query'),
    output: Path = typer.Option('.', '--output', '-o', help='Directory to output the results to'),
    debug: bool = typer.Option(False, '--debug', '-d', help='Enable [green]DEBUG[/] output')
):

    init_logger(debug)
    hunter = Hunter(host, username, password, edge_filter, limit_results, output)
    hunter.get_summary()
    hunter.close()



if __name__ == '__main__':
    app(prog_name='bloodhunt')
