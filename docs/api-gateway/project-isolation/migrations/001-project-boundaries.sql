BEGIN;
CREATE SCHEMA IF NOT EXISTS platform;
CREATE TABLE platform.projects (
 id char(26) PRIMARY KEY, application_slug text NOT NULL,
 environment text NOT NULL CHECK (environment IN ('development','staging','production')),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(application_slug,environment), CHECK (id ~ '^[0-9A-HJKMNP-TV-Z]{26}$')
);
CREATE TABLE platform.project_memberships (
 project_id char(26) NOT NULL REFERENCES platform.projects(id) ON DELETE RESTRICT,
 user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 membership_role text NOT NULL DEFAULT 'member' CHECK (membership_role IN ('owner','member','read_only')),
 status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(project_id,user_id)
);
CREATE INDEX project_memberships_user_status_idx ON platform.project_memberships(user_id,status,project_id);
CREATE TABLE platform.project_storage_buckets (
 project_id char(26) PRIMARY KEY REFERENCES platform.projects(id) ON DELETE RESTRICT,
 bucket_id text NOT NULL UNIQUE REFERENCES storage.buckets(id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO platform.projects(id,application_slug,environment) VALUES
 ('01M71YVC332S8G77297GQA7HVN','vishwa-guru','development'),
 ('01M71YVC337RW1YS5RSGW0SWFN','vishwa-guru','staging'),
 ('01M71YVC337C0NQQ9FY8B3NH2H','vishwa-guru','production');

DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['audit_events','campaigns','cms_media_assets','contact_information','donations','donors','events','failure_states','file_assets','galleries','gallery_images','hero_banner_pages','hero_banners','idempotency_keys','payment_document_assets','payment_providers','payments','receipts','static_page_references','static_pages','trust_identities','webhook_events'] LOOP
  EXECUTE format('ALTER TABLE public.%I ADD COLUMN project_id char(26)',t);
  EXECUTE format('UPDATE public.%I SET project_id=%L',t,'01M71YVC337C0NQQ9FY8B3NH2H');
  EXECUTE format('ALTER TABLE public.%I ALTER COLUMN project_id SET NOT NULL',t);
  EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY(project_id) REFERENCES platform.projects(id) ON DELETE RESTRICT',t,t||'_project_id_fk');
  EXECUTE format('CREATE INDEX %I ON public.%I(project_id)',t||'_project_id_idx',t);
 END LOOP;
END $$;

DO $$
DECLARE t text; k text;
BEGIN
 FOREACH t IN ARRAY ARRAY['audit_events','campaigns','cms_media_assets','contact_information','donations','donors','events','failure_states','file_assets','galleries','gallery_images','hero_banners','payment_document_assets','payments','payment_providers','receipts','static_page_references','static_pages','webhook_events'] LOOP
  k := CASE WHEN t='payment_providers' THEN 'code' ELSE 'id' END;
  EXECUTE format('CREATE UNIQUE INDEX %I ON public.%I(project_id,%I)',t||'_project_key',t,k);
 END LOOP;
END $$;
CREATE UNIQUE INDEX trust_identities_project_key ON public.trust_identities(project_id,key);
CREATE UNIQUE INDEX hero_banner_pages_project_pair_key ON public.hero_banner_pages(project_id,hero_banner_id,static_page_id);

DO $$
DECLARE r record;
BEGIN
 FOR r IN SELECT * FROM (VALUES
 ('campaigns','cover_image_file_id','cms_media_assets','id','campaigns_cover_project_fk'),
 ('cms_media_assets','file_asset_id','file_assets','id','cms_media_file_project_fk'),
 ('donations','campaign_id','campaigns','id','donations_campaign_project_fk'),
 ('donations','donor_id','donors','id','donations_donor_project_fk'),
 ('events','banner_file_id','cms_media_assets','id','events_banner_project_fk'),
 ('failure_states','payment_id','payments','id','failure_payment_project_fk'),
 ('galleries','cover_image_file_id','cms_media_assets','id','galleries_cover_project_fk'),
 ('gallery_images','file_asset_id','cms_media_assets','id','gallery_image_file_project_fk'),
 ('gallery_images','gallery_id','galleries','id','gallery_images_gallery_project_fk'),
 ('hero_banner_pages','hero_banner_id','hero_banners','id','hero_page_banner_project_fk'),
 ('hero_banner_pages','static_page_id','static_pages','id','hero_page_page_project_fk'),
 ('hero_banners','image_file_id','cms_media_assets','id','hero_banner_image_project_fk'),
 ('hero_banners','mobile_image_file_id','cms_media_assets','id','hero_banner_mobile_project_fk'),
 ('payment_document_assets','donation_id','donations','id','pda_donation_project_fk'),
 ('payment_document_assets','file_asset_id','file_assets','id','pda_file_project_fk'),
 ('payment_document_assets','payment_id','payments','id','pda_payment_project_fk'),
 ('payment_document_assets','receipt_id','receipts','id','pda_receipt_project_fk'),
 ('payment_document_assets','superseded_by_id','payment_document_assets','id','pda_superseded_project_fk'),
 ('payments','donation_id','donations','id','payments_donation_project_fk'),
 ('receipts','certificate_80g_file_id','file_assets','id','receipts_80g_file_project_fk'),
 ('receipts','campaign_id','campaigns','id','receipts_campaign_project_fk'),
 ('receipts','donation_id','donations','id','receipts_donation_project_fk'),
 ('receipts','payment_id','payments','id','receipts_payment_project_fk'),
 ('receipts','receipt_file_id','file_assets','id','receipts_file_project_fk'),
 ('static_page_references','static_page_id','static_pages','id','static_refs_page_project_fk'),
 ('webhook_events','related_payment_id','payments','id','webhook_payment_project_fk')
 ) AS f(src,src_col,dst,dst_col,cname)
 LOOP
  EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY(project_id,%I) REFERENCES public.%I(project_id,%I) NOT VALID',r.src,r.cname,r.src_col,r.dst,r.dst_col);
  EXECUTE format('ALTER TABLE public.%I VALIDATE CONSTRAINT %I',r.src,r.cname);
 END LOOP;
END $$;

CREATE VIEW public.campaign_progress AS
SELECT d.project_id,d.campaign_id,d.currency_code,sum(d.amount_minor)::bigint AS raised_amount_minor,
 count(*)::bigint AS completed_donation_count,count(DISTINCT d.donor_id)::bigint AS unique_donor_count
FROM public.donations d JOIN public.campaigns c ON c.project_id=d.project_id AND c.id=d.campaign_id
WHERE d.state='completed' AND d.deleted_at IS NULL AND c.deleted_at IS NULL AND c.state IN ('active','completed')
GROUP BY d.project_id,d.campaign_id,d.currency_code;
COMMIT;

