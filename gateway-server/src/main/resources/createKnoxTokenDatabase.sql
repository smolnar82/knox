CREATE TABLE knox_tokens (
   token_id varchar(128),
   issue_time bigint,
   expiration bigint,
   max_lifetime bigint,
   unused boolean,
   primary key(token_id)
)