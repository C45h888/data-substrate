-- Project-scoped logical Storage buckets; existing default bucket remains intact.
BEGIN;
INSERT INTO storage.buckets (
  id, download_expiration, min_upload_file_size, max_upload_file_size,
  cache_control, presigned_urls_enabled
)
SELECT v.bucket_id, d.download_expiration, d.min_upload_file_size,
       d.max_upload_file_size, d.cache_control, d.presigned_urls_enabled
FROM (VALUES
  ('01M71YVC332S8G77297GQA7HVN','vg-development'),
  ('01M71YVC337RW1YS5RSGW0SWFN','vg-staging'),
  ('01M71YVC337C0NQQ9FY8B3NH2H','vg-production')
) AS v(project_id,bucket_id)
CROSS JOIN (SELECT download_expiration,min_upload_file_size,max_upload_file_size,cache_control,presigned_urls_enabled FROM storage.buckets WHERE id='default') d
ON CONFLICT (id) DO NOTHING;

INSERT INTO platform.project_storage_buckets(project_id,bucket_id) VALUES
  ('01M71YVC332S8G77297GQA7HVN','vg-development'),
  ('01M71YVC337RW1YS5RSGW0SWFN','vg-staging'),
  ('01M71YVC337C0NQQ9FY8B3NH2H','vg-production')
ON CONFLICT (project_id) DO NOTHING;
COMMIT;

