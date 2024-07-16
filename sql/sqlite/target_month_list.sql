SELECT
    strftime('%Y-%m-%d', dates.date) AS date,
    strftime('%w', dates.date) + 1 AS day_of_week,
    CASE
        WHEN COUNT(stamps.date) > 0 THEN 1
        ELSE 0
END AS has_registered
FROM
    (
        SELECT DATE(julianday(DATE(/*year*/'2024' || '-' || printf('%02d', /*month*/'5' ) || '-01')) + t1.i + t2.i * 31 ) AS date
        FROM (SELECT 0 AS i UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10 UNION ALL SELECT 11 UNION ALL SELECT 12 UNION ALL SELECT 13 UNION ALL SELECT 14 UNION ALL SELECT 15 UNION ALL SELECT 16 UNION ALL SELECT 17 UNION ALL SELECT 18 UNION ALL SELECT 19 UNION ALL SELECT 20 UNION ALL SELECT 21 UNION ALL SELECT 22 UNION ALL SELECT 23 UNION ALL SELECT 24 UNION ALL SELECT 25 UNION ALL SELECT 26 UNION ALL SELECT 27 UNION ALL SELECT 28 UNION ALL SELECT 29 UNION ALL SELECT 30) AS t1,
             (SELECT 0 AS i UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 ) AS t2
        WHERE DATE(julianday(DATE(/*year*/'2024' || '-' || printf('%02d', /*month*/'5' ) || '-01')) + t1.i + t2.i * 31 ) <= DATE(/*year*/'2024' || '-' || printf('%02d', /*month*/'5' ) || '-01', '+1 month', '-1 day')
    ) AS dates
LEFT JOIN
    stamps ON DATE(stamps.date) = dates.date
GROUP BY
    dates.date
ORDER BY
    dates.date;
