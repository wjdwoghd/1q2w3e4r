BEGIN IMMEDIATE;
CREATE TABLE business_services (
    service_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(service_id)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0)
);
CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(asset_id)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    business_service_id TEXT NOT NULL REFERENCES business_services(service_id),
    environment TEXT NOT NULL CHECK (environment IN ('production','development','test','staging')),
    internet_exposed INTEGER NOT NULL CHECK (internet_exposed IN (0,1)),
    business_criticality TEXT NOT NULL CHECK (business_criticality IN ('critical','high','medium','low')),
    customer_information INTEGER NOT NULL CHECK (customer_information IN (0,1)),
    credit_information INTEGER NOT NULL CHECK (credit_information IN (0,1)),
    vendor TEXT NOT NULL CHECK (length(trim(vendor)) > 0),
    owner TEXT NOT NULL CHECK (length(trim(owner)) > 0),
    patch_status TEXT NOT NULL CHECK (patch_status IN ('unknown','pending','applied','deferred'))
);
CREATE INDEX assets_business_service_idx ON assets(business_service_id);
PRAGMA user_version = 1;
COMMIT;
