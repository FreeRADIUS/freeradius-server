/*
 * --- Peter Nixon [ codemonkey@peternixon.net ]
 *
 */

CREATE TABLE billing_record (
  Id BIGSERIAL PRIMARY KEY,
  local_SetupTime timestamp,
  start_time NUMERIC(11),
  duration INTEGER,
  service_code CHAR(1),
  phone_number VARCHAR(24),
  ip_addr_ingress INET,
  ip_addr_egress INET,
  bill_type CHAR(1),
  disconnect_reason CHAR(2),
  extended_reason_code CHAR(2),
  dialed_number VARCHAR(30),
  codec VARCHAR(20),
  h323ConfID VARCHAR(64)
);
create UNIQUE index combo on billing_record (start_time, ip_addr_ingress, h323ConfID);
