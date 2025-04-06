from werkzeug.security import generate_password_hash

def populate_db():
    from app import db, app, User, Organization

    with app.app_context():
        db.create_all()

        if not User.query.filter_by(email='sysadmin@dpat.org').first():
            sysadmin = User(
                email='sysadmin@dpat.org',
                password=generate_password_hash('sysadminpass', method='scrypt'),
                role='sysadmin',
                first_name='System',
                last_name='Admin'
            )
            db.session.add(sysadmin)
            db.session.commit()
            print("Sysadmin user created!")

        shu_org = Organization.query.filter_by(name='Sacred Heart University').first()
        if not shu_org:
            shu_org = Organization(
                name='Sacred Heart University',
                admin_id=None
            )
            db.session.add(shu_org)
            db.session.commit()
            print("SHU organization created!")

        if not User.query.filter_by(email='admin@shu.edu').first():
            shu_admin = User(
                email='admin@shu.edu',
                password=generate_password_hash('shuadminpass', method='scrypt'),
                role='admin',
                first_name='SHU',
                last_name='Admin',
                organization_id=shu_org.id
            )
            db.session.add(shu_admin)
            db.session.commit()
            print("SHU admin created!")

            shu_org.admin_id = shu_admin.id
            db.session.commit()

        if not User.query.filter_by(email='user@shu.edu').first():
            shu_user = User(
                email='user@shu.edu',
                password=generate_password_hash('shuuserpass', method='scrypt'),
                role='user',
                first_name='SHU',
                last_name='User',
                organization_id=shu_org.id
            )
            db.session.add(shu_user)
            db.session.commit()
            print("SHU user created!")

        print("Database population complete!")

if __name__ == '__main__':
    populate_db()