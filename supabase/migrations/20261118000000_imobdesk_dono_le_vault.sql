-- Cofre do Imobdesk: o imobdesk_dono passa a ler e gravar SÓ os segredos do Imobdesk (nome com prefixo imobdesk_).
--
-- Problema: desde a 90_multiempresa, as funções do Imobdesk que leem ou gravam no Vault são do imobdesk_dono. A 90 deu ao
-- dono USAGE no schema vault, SELECT/DELETE em vault.secrets e vault.decrypted_secrets e EXECUTE em create_secret e
-- update_secret, mas não as funções internas de cripto. Resultado:
--   * toda leitura falha com 42501 "permission denied for function _crypto_aead_det_decrypt" (3 vezes por minuto, nos
--     crons imobdesk-email-1min, imobdesk-ia-1min e imobdesk-whatsapp-1min; também OpenWA, Zenvia, TOTVS, SIENGE, Google);
--   * gravar segredo (senha de e-mail, token Zenvia, chave OpenWA etc.) também falha (_crypto_aead_det_encrypt);
--   * e o dono podia ler a lista e APAGAR segredos de qualquer outro sistema do banco compartilhado.
--
-- Correção (sem dar ao dono a cripto do Vault inteiro):
--   1. Quatro funções de cofre, do postgres, que só o imobdesk_dono executa e que só enxergam nomes 'imobdesk_%':
--      vault_segredos() (leitura), vault_criar(), vault_atualizar(), vault_apagar().
--   2. As funções do Imobdesk que citam vault.* são reescritas para usar as de cofre (mesma técnica do passo 7 do
--      aplicar_multiempresa). O resto do corpo não muda; a função continua do dono e sob a RLS de empresa.
--   3. O acesso direto do imobdesk_dono ao Vault é retirado.
--   4. aplicar_multiempresa() ganha as quatro na lista do postgres (senão a próxima passada as daria ao dono).
-- Tudo numa transação: se alguma função ainda citar o vault direto, ou a leitura pelo dono não funcionar, nada fica.
--
-- Atenção: as migrations antigas que criam essas funções ainda citam vault.*. Reaplicar uma delas volta a quebrar a
-- função; ao recriar, use as funções de cofre.

begin;

-- ---------- 1. Funções de cofre (dono postgres) ----------

/** Segredos do Imobdesk já abertos. Usada no lugar de vault.decrypted_secrets e de vault.secrets. */
create or replace function imobdesk.vault_segredos()
returns table (id uuid, name text, decrypted_secret text)
language sql
stable
security definer
set search_path = ''
as $$
  select s.id, s.name, s.decrypted_secret from vault.decrypted_secrets s where s.name like 'imobdesk\_%';
$$;

create or replace function imobdesk.vault_criar(p_valor text, p_nome text, p_descricao text default '')
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_nome is null or p_nome not like 'imobdesk\_%' then
    raise exception 'imobdesk: segredo fora do cofre do Imobdesk (o nome precisa começar com imobdesk_)';
  end if;
  return vault.create_secret(p_valor, p_nome, coalesce(p_descricao, ''));
end;
$$;

create or replace function imobdesk.vault_atualizar(p_id uuid, p_valor text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from vault.secrets s where s.id = p_id and s.name like 'imobdesk\_%') then
    raise exception 'imobdesk: segredo não encontrado no cofre do Imobdesk';
  end if;
  perform vault.update_secret(p_id, p_valor);
end;
$$;

create or replace function imobdesk.vault_apagar(p_ids uuid[])
returns void
language sql
security definer
set search_path = ''
as $$
  delete from vault.secrets s where s.id = any (p_ids) and s.name like 'imobdesk\_%';
$$;

revoke all on function imobdesk.vault_segredos(), imobdesk.vault_criar(text, text, text),
  imobdesk.vault_atualizar(uuid, text), imobdesk.vault_apagar(uuid[])
  from public, anon, authenticated, service_role;
grant execute on function imobdesk.vault_segredos(), imobdesk.vault_criar(text, text, text),
  imobdesk.vault_atualizar(uuid, text), imobdesk.vault_apagar(uuid[])
  to imobdesk_dono;

-- ---------- 2. aplicar_multiempresa: as quatro ficam com o postgres ----------
-- Igual à 20261024000400, só com 'vault_segredos', 'vault_criar', 'vault_atualizar', 'vault_apagar' em v_do_postgres.

create or replace function imobdesk.aplicar_multiempresa()
returns text
language plpgsql
set search_path = ''
as $$
declare
  v_modelo constant uuid := '00000000-0000-0000-0000-000000000001';
  v_globais constant text[] := array['empresas', 'admins_wsa', 'usuario_preferencias', 'security_attempts', 'security_auth_control',
    'security_config', 'security_events', 'security_ip_blocks', 'security_secret', 'security_sessions'];
  -- Funções que ficam com o postgres: leem por cima da RLS de empresa de propósito, escrevem no auth, são
  -- chamadas pelo Auth (hook) ou são o cofre do Imobdesk. Cada uma filtra a empresa (ou o prefixo) por conta própria.
  v_do_postgres constant text[] := array['empresa_atual', 'dominio_permitido', 'eh_admin_wsa', 'aplicar_multiempresa',
    'para_cada_empresa', 'empresa_copiar_modelo', 'minhas_empresas', 'trocar_empresa', 'minhas_preferencias', 'salvar_tema',
    'criar_empresa', 'listar_empresas_wsa', 'encerrar_sessao', 'security_password_verification_hook',
    'empresa_de', 'empresas_ativas', 'empresa_por_numero', 'empresa_por_sessao_openwa', 'empresa_por_estado_oauth',
    'empresa_por_mensagem_zenvia', 'security_sessao_valida',
    'vault_segredos', 'vault_criar', 'vault_atualizar', 'vault_apagar'];
  t record;
  k record;
  v_fks jsonb := '[]'::jsonb;
  v_def text;
  v_cols text;
  v_tabelas int := 0;
begin
  -- 1. tenant_id nas tabelas que ainda não têm (default constante: preenche sem disparar gatilhos).
  for t in
    select c.relname from pg_class c
     where c.relnamespace = 'imobdesk'::regnamespace and c.relkind = 'r' and not (c.relname = any (v_globais))
       and not exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = 'tenant_id' and not a.attisdropped)
  loop
    execute format('alter table imobdesk.%I add column tenant_id uuid not null default %L', t.relname, v_modelo);
    execute format('alter table imobdesk.%I alter column tenant_id set default imobdesk.empresa_atual()', t.relname);
    execute format('alter table imobdesk.%I add constraint %I foreign key (tenant_id) references imobdesk.empresas (id) on delete cascade',
      t.relname, left(t.relname, 50) || '_tenant_fk');
    v_tabelas := v_tabelas + 1;
  end loop;

  -- 2. Chaves estrangeiras entre tabelas do app sem tenant_id: guarda e remove (voltam compostas no passo 5).
  for k in
    select c.conname, c.conrelid::regclass::text tabela, pg_get_constraintdef(c.oid) def
      from pg_constraint c
      join pg_class r on r.oid = c.confrelid
     where c.contype = 'f' and c.connamespace = 'imobdesk'::regnamespace
       and r.relnamespace = 'imobdesk'::regnamespace and not (r.relname = any (v_globais))
       and not exists (select 1 from pg_attribute a where a.attrelid = c.conrelid and a.attname = 'tenant_id' and a.attnum = any (c.conkey))
  loop
    v_fks := v_fks || jsonb_build_object('tabela', k.tabela, 'nome', k.conname, 'def', k.def);
    execute format('alter table %s drop constraint %I', k.tabela, k.conname);
  end loop;

  -- 3. Primárias e únicas passam a valer por empresa.
  for k in
    select c.conname, c.conrelid::regclass::text tabela, pg_get_constraintdef(c.oid) def
      from pg_constraint c
      join pg_class r on r.oid = c.conrelid
     where c.contype in ('p', 'u') and c.connamespace = 'imobdesk'::regnamespace and not (r.relname = any (v_globais))
       and not exists (select 1 from pg_attribute a where a.attrelid = c.conrelid and a.attname = 'tenant_id' and a.attnum = any (c.conkey))
  loop
    execute format('alter table %s drop constraint %I', k.tabela, k.conname);
    execute format('alter table %s add constraint %I %s', k.tabela, k.conname, regexp_replace(k.def, '\(', '(tenant_id, '));
  end loop;

  -- 4. Índices únicos soltos (parciais e por expressão) também.
  for k in
    select i.indexrelid::regclass::text idx, pg_get_indexdef(i.indexrelid) def
      from pg_index i
      join pg_class r on r.oid = i.indrelid
     where r.relnamespace = 'imobdesk'::regnamespace and i.indisunique and not (r.relname = any (v_globais))
       and not exists (select 1 from pg_constraint x where x.conindid = i.indexrelid)
       and not exists (select 1 from pg_attribute a where a.attrelid = i.indrelid and a.attname = 'tenant_id' and a.attnum = any (i.indkey::int2[]))
  loop
    execute format('drop index %s', k.idx);
    execute regexp_replace(k.def, 'USING (\w+) \(', 'USING \1 (tenant_id, ');
  end loop;

  -- 5. Estrangeiras de volta, compostas. SET NULL só nas colunas próprias (tenant_id é NOT NULL).
  --    DEFERRABLE INITIALLY IMMEDIATE: mesmo comportamento de antes, mas a cópia da Modelo pode adiar a checagem.
  for k in select * from jsonb_to_recordset(v_fks) as x(tabela text, nome text, def text)
  loop
    v_cols := substring(k.def from '^FOREIGN KEY \(([^)]*)\)');
    v_def := regexp_replace(k.def, '^FOREIGN KEY \(([^)]*)\) REFERENCES ([^(]+)\(([^)]*)\)',
                            'FOREIGN KEY (tenant_id, \1) REFERENCES \2(tenant_id, \3)');
    v_def := regexp_replace(v_def, 'ON DELETE SET (NULL|DEFAULT)', 'ON DELETE SET \1 (' || v_cols || ')');
    if v_def !~ 'DEFERRABLE' then
      v_def := v_def || ' DEFERRABLE INITIALLY IMMEDIATE';
    end if;
    execute format('alter table %s add constraint %I %s', k.tabela, k.nome, v_def);
  end loop;

  -- 6. RLS forçada: a restritiva vale para todos (inclusive o dono); a permissiva do dono libera as funções.
  for t in
    select c.relname from pg_class c
     where c.relnamespace = 'imobdesk'::regnamespace and c.relkind = 'r' and not (c.relname = any (v_globais))
  loop
    execute format('alter table imobdesk.%I enable row level security, force row level security', t.relname);
    execute format('drop policy if exists imobdesk_tenant on imobdesk.%I', t.relname);
    execute format('create policy imobdesk_tenant on imobdesk.%I as restrictive for all to public
                      using (tenant_id = (select imobdesk.empresa_atual())) with check (tenant_id = (select imobdesk.empresa_atual()))', t.relname);
    execute format('drop policy if exists imobdesk_dono on imobdesk.%I', t.relname);
    execute format('create policy imobdesk_dono on imobdesk.%I as permissive for all to imobdesk_dono using (true) with check (true)', t.relname);
  end loop;

  -- 7. ON CONFLICT (cols) nas funções: o alvo precisa incluir tenant_id (as tabelas security_* são globais).
  for k in
    select p.oid, pg_get_functiondef(p.oid) def
      from pg_proc p
     where p.pronamespace = 'imobdesk'::regnamespace and p.prokind = 'f'
       and p.prosrc ~* 'on conflict \((?!tenant_id|user_hash|session_id|ip_hash)'
  loop
    execute regexp_replace(k.def, 'on conflict \((?!tenant_id|user_hash|session_id|ip_hash)', 'on conflict (tenant_id, ', 'gi');
  end loop;

  -- 8. Dono: tabelas (e as sequências delas) e funções passam ao imobdesk_dono, menos as de v_do_postgres.
  for t in select c.relname from pg_class c where c.relnamespace = 'imobdesk'::regnamespace and c.relkind = 'r'
  loop
    execute format('alter table imobdesk.%I owner to imobdesk_dono', t.relname);
  end loop;
  for k in
    select p.oid::regprocedure::text fn, p.proname, pg_get_userbyid(p.proowner) dono
      from pg_proc p where p.pronamespace = 'imobdesk'::regnamespace
  loop
    if k.proname = any (v_do_postgres) then
      if k.dono <> 'postgres' then
        execute format('alter function %s owner to postgres', k.fn);
      end if;
    elsif k.dono <> 'imobdesk_dono' then
      execute format('alter function %s owner to imobdesk_dono', k.fn);
    end if;
  end loop;

  return format('%s tabela(s) nova(s) com tenant_id; %s chave(s) estrangeira(s) refeita(s).', v_tabelas, jsonb_array_length(v_fks));
end;
$$;

revoke all on function imobdesk.aplicar_multiempresa() from public, anon, authenticated, service_role;

-- ---------- 3. Funções do Imobdesk passam a usar o cofre ----------

do $$
declare
  k record;
  v_def text;
  v_cofre constant text[] := array['vault_segredos', 'vault_criar', 'vault_atualizar', 'vault_apagar'];
  v_total int := 0;
begin
  for k in
    select p.oid::regprocedure::text fn, pg_get_functiondef(p.oid) def
      from pg_proc p
     where p.pronamespace = 'imobdesk'::regnamespace and p.prokind = 'f'
       and p.prosrc ~* 'vault\.' and not (p.proname = any (v_cofre))
  loop
    v_def := k.def;
    -- apagar (antes da troca genérica de vault.secrets)
    v_def := regexp_replace(v_def, 'delete from vault\.secrets where id in \(([^)]*)\);',
                            'perform imobdesk.vault_apagar(array[\1]);', 'gi');
    v_def := regexp_replace(v_def, 'delete from vault\.secrets where id = (\(select [^;]*\));',
                            'perform imobdesk.vault_apagar(array[\1]);', 'gi');
    -- ler (vault.secrets só é consultado por id e nome, que vault_segredos() também devolve)
    v_def := regexp_replace(v_def, 'vault\.decrypted_secrets', 'imobdesk.vault_segredos()', 'gi');
    v_def := regexp_replace(v_def, 'vault\.secrets', 'imobdesk.vault_segredos()', 'gi');
    -- gravar
    v_def := regexp_replace(v_def, 'vault\.create_secret\(', 'imobdesk.vault_criar(', 'gi');
    v_def := regexp_replace(v_def, 'vault\.update_secret\(', 'imobdesk.vault_atualizar(', 'gi');

    -- Sensível a maiúsculas: comentários como "sai do Vault." não são referência ao schema.
    if v_def ~ '(^|[^_a-zA-Z])vault\.' then
      raise exception 'imobdesk: % ainda cita o vault direto depois da troca', k.fn;
    end if;
    execute v_def;
    v_total := v_total + 1;
    raise notice 'imobdesk: % passa a usar o cofre', k.fn;
  end loop;
  raise notice 'imobdesk: % função(ões) reescrita(s)', v_total;
end;
$$;

-- ---------- 4. Sem acesso direto do dono ao Vault ----------

revoke execute on function vault.create_secret(text, text, text, uuid), vault.update_secret(uuid, text, text, text, uuid)
  from imobdesk_dono;
revoke all on vault.secrets, vault.decrypted_secrets from imobdesk_dono;
revoke usage on schema vault from imobdesk_dono;

select imobdesk.aplicar_multiempresa();

-- ---------- 5. Conferência (falha = nada é aplicado) ----------

do $$
declare
  v_restantes text;
begin
  select string_agg(p.oid::regprocedure::text, ', ') into v_restantes
    from pg_proc p
   where p.pronamespace = 'imobdesk'::regnamespace and p.prosrc ~ '(^|[^_a-zA-Z])vault\.'
     and p.proname not in ('vault_segredos', 'vault_criar', 'vault_atualizar', 'vault_apagar');
  if v_restantes is not null then
    raise exception 'imobdesk: ainda citam o vault direto: %', v_restantes;
  end if;

  if exists (select 1 from pg_proc p
              where p.pronamespace = 'imobdesk'::regnamespace
                and p.proname in ('vault_segredos', 'vault_criar', 'vault_atualizar', 'vault_apagar')
                and pg_get_userbyid(p.proowner) <> 'postgres') then
    raise exception 'imobdesk: as funções de cofre precisam ser do postgres';
  end if;

  if has_schema_privilege('imobdesk_dono', 'vault', 'usage')
     or has_table_privilege('imobdesk_dono', 'vault.decrypted_secrets', 'select')
     or has_table_privilege('imobdesk_dono', 'vault.secrets', 'delete') then
    raise exception 'imobdesk: o imobdesk_dono ainda tem acesso direto ao Vault';
  end if;

  -- As três chaves dos crons, lidas pelas funções do dono (o valor não é exibido).
  if imobdesk.at_email_cron_chave() is null or imobdesk.at_ia_cron_chave() is null or imobdesk.at_whatsapp_cron_chave() is null then
    raise exception 'imobdesk: as chaves dos crons não foram lidas pelo cofre';
  end if;

  raise notice 'imobdesk: cofre conferido';
end;
$$;

commit;

notify pgrst, 'reload schema';
