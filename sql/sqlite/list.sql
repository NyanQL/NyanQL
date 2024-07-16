SELECT
    strftime('%Y-%m-%d', dates.date) AS date,
    strftime('%w', dates.date) + 1 AS day_of_week,
    CASE
        WHEN COUNT(stamps.date) > 0 THEN 1
        ELSE 0
END AS has_registered
FROM
    (
        SELECT DATE(julianday(date('now', 'start of month')) + t1.i + t2.i * 31) AS date
        FROM (SELECT 0 AS i UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10 UNION SELECT 11 UNION SELECT 12 UNION SELECT 13 UNION SELECT 14 UNION SELECT 15 UNION SELECT 16 UNION SELECT 17 UNION SELECT 18 UNION SELECT 19 UNION SELECT 20 UNION SELECT 21 UNION SELECT 22 UNION SELECT 23 UNION SELECT 24 UNION SELECT 25 UNION SELECT 26 UNION SELECT 27 UNION SELECT 28 UNION SELECT 29 UNION SELECT 30) AS t1,
             (SELECT 0 AS i UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4) AS t2
        WHERE DATE(julianday(date('now', 'start of month')) + t1.i + t2.i * 31) <= date('now', 'start of month', '+1 month', '-1 day')
    ) AS dates
LEFT JOIN
    stamps ON DATE(stamps.date) = dates.date
GROUP BY
    dates.date
ORDER BY
    dates.date;