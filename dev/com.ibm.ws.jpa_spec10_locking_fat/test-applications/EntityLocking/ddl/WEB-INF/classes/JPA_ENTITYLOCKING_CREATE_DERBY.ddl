CREATE TABLE ${schemaname}.EL10LockEntA (ID INTEGER NOT NULL, STRDATA VARCHAR(255), ENTB_OTO INTEGER, ENTB_MTO INTEGER, VERSION INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.EL10LockEntB (ID INTEGER NOT NULL, STRDATA VARCHAR(255), VERSION INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.EL10LEOMJT (ENTA INTEGER NOT NULL, ENTB INTEGER NOT NULL);
CREATE TABLE ${schemaname}.EL10LEMMJT (ENTA INTEGER NOT NULL, ENTB INTEGER NOT NULL);