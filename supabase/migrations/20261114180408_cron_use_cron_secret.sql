-- Lich nhac kham dung CRON_SECRET (header x-cron-secret). Can Vault: supabase_project_url, cron_secret (tao tay, khong luu trong repo)
create or replace function public.trigger_pre_consult_reminder_scan()
returns jsonb language plpgsql security definer set search_path to 'public'
as $function$
declare v_url text; v_secret text; v_request_id bigint;
begin
  select decrypted_secret into v_url from vault.decrypted_secrets where name = 'supabase_project_url' limit 1;
  select decrypted_secret into v_secret from vault.decrypted_secrets where name = 'cron_secret' limit 1;
  if v_url is null or v_secret is null then
    return jsonb_build_object('skipped', true, 'reason', 'Vault secrets supabase_project_url / cron_secret not configured');
  end if;
  select net.http_post(
    url := rtrim(v_url, '/') || '/functions/v1/scan-pre-consult-reminders',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', v_secret),
    body := '{}'::jsonb
  ) into v_request_id;
  return jsonb_build_object('request_id', v_request_id);
exception
  when undefined_table then
    return jsonb_build_object('skipped', true, 'reason', 'pg_net or vault extension not available');
  when others then
    return jsonb_build_object('skipped', true, 'reason', SQLERRM);
end;
$function$;
