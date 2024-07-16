SELECT count(id) AS today_count
FROM stamps
WHERE DATE(date) = CURRENT_DATE;