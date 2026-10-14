-- Jason Stys: exact source/hostname search uses bound values, never interpolated SQL or wildcard guesses.
-- BEGIN CODE MAP (generated; python scripts/code_map.py)
-- END CODE MAP
SELECT identifier, time_ns, src, dst, protocol, dport, name
FROM events
WHERE src = ? OR dst = ? OR name = ?
ORDER BY time_ns, identifier
LIMIT ?;
