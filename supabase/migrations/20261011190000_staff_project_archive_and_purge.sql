-- Allow CPS staff to archive projects for routine cleanup and permanently purge
-- only projects that have first been archived.

drop policy if exists "CPS staff delete archived projects" on public.projects;
create policy "CPS staff delete archived projects"
on public.projects
for delete
to authenticated
using (
  (select private.is_cps_staff())
  and archived_at is not null
);

drop policy if exists "CPS staff delete archived project signoffs" on public.signoff_records;
create policy "CPS staff delete archived project signoffs"
on public.signoff_records
for delete
to authenticated
using (
  (select private.is_cps_staff())
  and exists (
    select 1
    from public.projects p
    where p.id = signoff_records.project_id
      and p.archived_at is not null
  )
);

create or replace function public.cps_purge_archived_project(p_project_id uuid)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_deleted_count integer;
begin
  if not coalesce(private.is_cps_staff(), false) then
    raise exception 'CPS staff access required';
  end if;

  -- Sign-offs reference commissioning runs and releases with RESTRICT, so remove
  -- them first. The project delete then cascades its remaining relational data.
  delete from public.signoff_records
  where project_id = p_project_id;

  delete from public.projects
  where id = p_project_id
    and archived_at is not null;

  get diagnostics v_deleted_count = row_count;
  return v_deleted_count = 1;
end;
$$;

revoke all on function public.cps_purge_archived_project(uuid) from public, anon;
grant execute on function public.cps_purge_archived_project(uuid) to authenticated;
