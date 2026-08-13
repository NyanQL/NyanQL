'use strict';

JSON.stringify({
  success: true,
  status: 200,
  result: nyanRunSQL('./sql/sqlite/list.sql', nyanAllParams)
});
