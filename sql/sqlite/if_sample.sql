SELECT id, date FROM stamps
/*BEGIN*/
WHERE
    /*IF id != null*/ id = /*id*/1 /*END*/
    /*IF id != null AND date != null */ AND /*END*/
    /*IF date != null*/ date = /*date*/"2024-06-25" /*END*/
/*END*/
;