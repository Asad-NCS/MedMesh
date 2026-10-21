# Privacy-check client and server

A researcher sends a query to one server that holds a synthetic patient table. The server returns a statistical summary, or refuses the query when it would reveal patient records or a group smaller than 5 people.

## Run

Start the server:

```
python server.py
```

In another terminal, send a query:

```
python client.py "mean age"
python client.py "get all records"
```

Run the allow and deny checks:

```
python test_queries.py
```

## What the server allows

- `count`
- `mean age`, `mean bmi`
- `count by sex`

## What the server denies

- Requests for rows or identifying fields, such as `get all records`, `get patient 4`, and `show name and diagnosis`
- Statistics on too few patients, such as `mean age where diagnosis = rare` and `count by diagnosis`
- Anything else it does not recognize

Allowed responses contain only the aggregate. They do not include patient ids, names, or rows.
