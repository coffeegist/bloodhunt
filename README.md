# bloodhunt


## Install
bloodhunt can be installed by cloning this repository and running pip3 install . and subsequently executed from PATH with bloodhunt, or by doing the following:
```
git clone https://github.com/???/bloodhunt
cd bloodhunt
poetry install
poetry run bloodhunt --help
```

## Usage

```bash
# Filter out edges from path (these are case sensisitve)

poetry run bloodhunt -u neo4j -p password_for_neo4j_db -q all -e 'HasSession' -e 'CanRDP'
```


## Examples

## Development
bloodhunt uses Poetry to manage dependencies. Install from source and setup for development with:
```
git clone https://github.com/???/bloodhunt
cd bloodhunt
poetry install
poetry run bloodhunt --help
```

## Credits
