SELECT TO_CHAR(dates.date, 'YYYY-MM-DD') AS date,
    EXTRACT(DOW FROM dates.date) AS day_of_week,
    CASE
        WHEN COUNT(stamps.date) > 0 THEN 1
        ELSE 0
END AS has_registered
FROM
    (
        SELECT (DATE_TRUNC('month', TO_DATE(CONCAT( cast( /*year*/'2024' as text ) , '-', cast( /*month*/'7' as text ), '-01'), 'YYYY-MM-DD'))
            + (t1.i + t2.i * 31) * INTERVAL '1 day')::date AS date
        FROM generate_series(0, 30) AS t1(i),
             generate_series(0, 4) AS t2(i)
        WHERE
            (
                DATE_TRUNC('month', TO_DATE(CONCAT(  cast( /*year*/'2024' as text ) , '-', cast( /*month*/'7' as text ) , '-01'), 'YYYY-MM-DD'))
                    + (t1.i + t2.i * 31) * INTERVAL '1 day'
            )::date <= (DATE_TRUNC('month', TO_DATE(
                CONCAT( cast( /*year*/'2024' as text ) , '-', cast( /*month*/'7' as text ) , '-01'), 'YYYY-MM-DD'))
                + '1 month'::interval - '1 day'::interval)::date
            ) AS dates
    LEFT JOIN stamps ON DATE(stamps.date) = dates.date
GROUP BY
    dates.date
ORDER BY
    dates.date;
