-- Old-style .doc files can carry macro viruses; the site only accepts .docx for Word documents now.
update storage.buckets
   set allowed_mime_types = array['application/pdf',
       'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
       'image/jpeg','image/png','image/heic','image/heif','image/webp']
 where id = 'case-files';
