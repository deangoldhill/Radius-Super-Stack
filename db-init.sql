CREATE DATABASE IF NOT EXISTS radius;
USE radius;

-- --------------------------------------------------------
-- FreeRADIUS Standard Authentication Tables
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS radcheck (
  id int(11) unsigned NOT NULL auto_increment,
  username varchar(64) NOT NULL default '',
  attribute varchar(64)  NOT NULL default '',
  op char(2) NOT NULL DEFAULT '==',
  value varchar(253) NOT NULL default '',
  PRIMARY KEY  (id),
  KEY username (username(32))
);

CREATE TABLE IF NOT EXISTS radreply (
  id int(11) unsigned NOT NULL auto_increment,
  username varchar(64) NOT NULL default '',
  attribute varchar(64) NOT NULL default '',
  op char(2) NOT NULL DEFAULT '=',
  value varchar(253) NOT NULL default '',
  PRIMARY KEY  (id),
  KEY username (username(32))
);

CREATE TABLE IF NOT EXISTS radgroupcheck (
  id int(11) unsigned NOT NULL auto_increment,
  groupname varchar(64) NOT NULL default '',
  attribute varchar(64)  NOT NULL default '',
  op char(2) NOT NULL DEFAULT '==',
  value varchar(253)  NOT NULL default '',
  PRIMARY KEY  (id),
  KEY groupname (groupname(32))
);

CREATE TABLE IF NOT EXISTS radgroupreply (
  id int(11) unsigned NOT NULL auto_increment,
  groupname varchar(64) NOT NULL default '',
  attribute varchar(64)  NOT NULL default '',
  op char(2) NOT NULL DEFAULT '=',
  value varchar(253)  NOT NULL default '',
  PRIMARY KEY  (id),
  KEY groupname (groupname(32))
);

CREATE TABLE IF NOT EXISTS radusergroup (
  id int(11) unsigned NOT NULL auto_increment,
  username varchar(64) NOT NULL default '',
  groupname varchar(64) NOT NULL default '',
  priority int(11) NOT NULL default '1',
  PRIMARY KEY  (id),
  KEY username (username(32))
);

-- --------------------------------------------------------
-- FreeRADIUS Auth & Accounting Logs (Includes IPv6 Fix)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS radpostauth (
  id int(11) NOT NULL auto_increment,
  username varchar(64) NOT NULL default '',
  pass varchar(64) NOT NULL default '',
  reply varchar(32) NOT NULL default '',
  authdate timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY  (id),
  KEY username (username)
);

CREATE TABLE IF NOT EXISTS radacct (
  radacctid bigint(21) NOT NULL auto_increment,
  acctsessionid varchar(64) NOT NULL default '',
  acctuniqueid varchar(32) NOT NULL default '',
  username varchar(64) NOT NULL default '',
  groupname varchar(64) NOT NULL default '',
  realm varchar(64) default '',
  nasipaddress varchar(15) NOT NULL default '',
  nasportid varchar(32) default NULL,
  nasporttype varchar(32) default NULL,
  acctstarttime datetime default NULL,
  acctupdatetime datetime default NULL,
  acctstoptime datetime default NULL,
  acctinterval int(12) default NULL,
  acctsessiontime int(12) unsigned default NULL,
  acctauthentic varchar(32) default NULL,
  connectinfo_start varchar(128) default NULL,
  connectinfo_stop varchar(128) default NULL,
  acctinputoctets bigint(20) default NULL,
  acctoutputoctets bigint(20) default NULL,
  calledstationid varchar(50) NOT NULL default '',
  callingstationid varchar(50) NOT NULL default '',
  acctterminatecause varchar(32) NOT NULL default '',
  servicetype varchar(32) default NULL,
  framedprotocol varchar(32) default NULL,
  framedipaddress varchar(15) NOT NULL default '',
  framedipv6address varchar(45) NOT NULL default '',
  framedipv6prefix varchar(45) NOT NULL default '',
  framedinterfaceid varchar(44) NOT NULL default '',
  delegatedipv6prefix varchar(45) NOT NULL default '',
  class varchar(64) default NULL,
  PRIMARY KEY (radacctid),
  UNIQUE KEY acctuniqueid (acctuniqueid),
  KEY username (username),
  KEY framedipaddress (framedipaddress),
  KEY acctsessionid (acctsessionid),
  KEY acctsessiontime (acctsessiontime),
  KEY acctstarttime (acctstarttime),
  KEY acctinterval (acctinterval),
  KEY acctstoptime (acctstoptime),
  KEY nasipaddress (nasipaddress)
);

-- --------------------------------------------------------
-- FreeRADIUS Client (NAS) Configuration
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS nas (
  id int(10) NOT NULL auto_increment,
  nasname varchar(128) NOT NULL,
  shortname varchar(32) default NULL,
  type varchar(30) default 'other',
  ports int(5) default NULL,
  secret varchar(60) NOT NULL DEFAULT 'secret',
  server varchar(64) default NULL,
  community varchar(50) default NULL,
  description varchar(200) default 'RADIUS Client',
  PRIMARY KEY  (id),
  KEY nasname (nasname)
);

-- --------------------------------------------------------
-- Custom Web Dashboard API Tables
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_admins (
  id int(11) NOT NULL AUTO_INCREMENT,
  username varchar(50) NOT NULL UNIQUE,
  password_hash varchar(255) NOT NULL,
  totp_secret varchar(32) DEFAULT NULL,
  api_key varchar(64) DEFAULT NULL UNIQUE,
  roles text,
  PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS api_audit (
  id int(11) NOT NULL AUTO_INCREMENT,
  admin_user varchar(50) NOT NULL,
  mode varchar(20) NOT NULL,
  action varchar(255) NOT NULL,
  created_at datetime NOT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS api_settings (
  key_name varchar(50) NOT NULL,
  key_value varchar(255) NOT NULL,
  PRIMARY KEY (key_name)
);

-- --------------------------------------------------------
-- Default Administrator Account
-- (Username: admin, Password: admin)
-- --------------------------------------------------------
INSERT IGNORE INTO api_admins (username, password_hash, roles) 
VALUES ('admin', '$2a$10$a1b2c3d4e5f6g7h8i9j0ku0PCd1jp9r7Nm6GlLr3FCL/FMS7/S1sS', 'reporting,active,history,authlogs,profiles,users,clients,admins,audit,write');
