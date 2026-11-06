-- Starter schema for the Khmer Inventory & Invoice website.
-- Run only in a new/test Supabase project after reviewing this file.
-- Never expose the service_role key in frontend code.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role text not null default 'staff'
    check (role in ('owner', 'manager', 'staff')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  code text unique,
  name text not null,
  unit text not null default 'pcs',
  quantity numeric(14,2) not null default 0 check (quantity >= 0),
  min_quantity numeric(14,2) not null default 0 check (min_quantity >= 0),
  cost_price numeric(14,2) not null default 0,
  sale_price numeric(14,2) not null default 0,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.contacts (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text,
  address text,
  contact_type text not null default 'customer'
    check (contact_type in ('customer', 'supplier', 'both')),
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.stock_movements (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id),
  movement_type text not null check (movement_type in ('in', 'out', 'adjustment')),
  quantity numeric(14,2) not null check (quantity > 0),
  unit_price numeric(14,2) not null default 0,
  reference text,
  note text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.invoices (
  id uuid primary key default gen_random_uuid(),
  invoice_number text not null unique,
  contact_id uuid references public.contacts(id),
  invoice_date date not null default current_date,
  subtotal numeric(14,2) not null default 0,
  discount numeric(14,2) not null default 0,
  total numeric(14,2) not null default 0,
  note text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.invoice_items (
  id uuid primary key default gen_random_uuid(),
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  product_id uuid references public.products(id),
  description text not null,
  quantity numeric(14,2) not null check (quantity > 0),
  unit_price numeric(14,2) not null default 0,
  line_total numeric(14,2) not null default 0
);

create or replace function public.current_user_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles
  where id = auth.uid() and active = true
$$;

create or replace function public.is_active_user()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and active = true
  )
$$;

create or replace function public.can_manage()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.current_user_role() in ('owner', 'manager')
$$;

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.contacts enable row level security;
alter table public.stock_movements enable row level security;
alter table public.invoices enable row level security;
alter table public.invoice_items enable row level security;

-- Profiles: users can view their own profile; owners can manage all profiles.
drop policy if exists "profile self read" on public.profiles;
create policy "profile self read" on public.profiles
for select to authenticated using (id = auth.uid() or public.current_user_role() = 'owner');

drop policy if exists "owner manage profiles" on public.profiles;
create policy "owner manage profiles" on public.profiles
for all to authenticated using (public.current_user_role() = 'owner')
with check (public.current_user_role() = 'owner');

-- All active team members can read business data.
-- Owners/managers can maintain catalogue and contacts.
drop policy if exists "active read products" on public.products;
create policy "active read products" on public.products
for select to authenticated using (public.is_active_user());

drop policy if exists "manager manage products" on public.products;
create policy "manager manage products" on public.products
for all to authenticated using (public.can_manage()) with check (public.can_manage());

drop policy if exists "active read contacts" on public.contacts;
create policy "active read contacts" on public.contacts
for select to authenticated using (public.is_active_user());

drop policy if exists "manager manage contacts" on public.contacts;
create policy "manager manage contacts" on public.contacts
for all to authenticated using (public.can_manage()) with check (public.can_manage());

-- Active staff can create stock movement records; managers can update/delete.
drop policy if exists "active read movements" on public.stock_movements;
create policy "active read movements" on public.stock_movements
for select to authenticated using (public.is_active_user());

drop policy if exists "active create movements" on public.stock_movements;
create policy "active create movements" on public.stock_movements
for insert to authenticated with check (public.is_active_user() and created_by = auth.uid());

drop policy if exists "manager update movements" on public.stock_movements;
create policy "manager update movements" on public.stock_movements
for update to authenticated using (public.can_manage()) with check (public.can_manage());

drop policy if exists "manager delete movements" on public.stock_movements;
create policy "manager delete movements" on public.stock_movements
for delete to authenticated using (public.can_manage());

-- Active users can read/create invoices and invoice lines.
drop policy if exists "active read invoices" on public.invoices;
create policy "active read invoices" on public.invoices
for select to authenticated using (public.is_active_user());

drop policy if exists "active create invoices" on public.invoices;
create policy "active create invoices" on public.invoices
for insert to authenticated with check (public.is_active_user() and created_by = auth.uid());

drop policy if exists "manager update invoices" on public.invoices;
create policy "manager update invoices" on public.invoices
for update to authenticated using (public.can_manage()) with check (public.can_manage());

drop policy if exists "manager delete invoices" on public.invoices;
create policy "manager delete invoices" on public.invoices
for delete to authenticated using (public.can_manage());

drop policy if exists "active read invoice items" on public.invoice_items;
create policy "active read invoice items" on public.invoice_items
for select to authenticated using (public.is_active_user());

drop policy if exists "active create invoice items" on public.invoice_items;
create policy "active create invoice items" on public.invoice_items
for insert to authenticated with check (public.is_active_user());

drop policy if exists "manager update invoice items" on public.invoice_items;
create policy "manager update invoice items" on public.invoice_items
for update to authenticated using (public.can_manage()) with check (public.can_manage());

drop policy if exists "manager delete invoice items" on public.invoice_items;
create policy "manager delete invoice items" on public.invoice_items
for delete to authenticated using (public.can_manage());

-- IMPORTANT: The first owner must be assigned manually after creating their
-- Auth user. In SQL Editor, replace the UUID with the user's auth.users id:
-- update public.profiles set role = 'owner' where id = 'YOUR-AUTH-USER-UUID';
--
-- Add a profile row for each newly created Auth user:
-- insert into public.profiles (id, display_name, role)
-- values ('AUTH-USER-UUID', 'Admin name', 'manager');
--
-- This starter schema does not yet implement atomic stock updates, invoice
-- numbering, or frontend Auth/database integration. Add tested RPC functions
-- for stock/invoice transactions before using it with live business data.
