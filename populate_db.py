from app import db, app, User, Organization
from werkzeug.security import generate_password_hash
from datetime import datetime

def populate_db():
    with app.app_context():
        # Drop and recreate the database (optional if already done)
        db.drop_all()
        db.create_all()

        # Create sysadmin user
        sysadmin = User(
            email='sysadmin@dpat.org',
            password=generate_password_hash('sysadminpass'),
            role='sysadmin',
            first_name='System',
            last_name='Admin'
        )
        db.session.add(sysadmin)
        db.session.commit()  # Commit sysadmin to get an ID

        # Create Sacred Heart University organization
        shu_org = Organization(
            name='Sacred Heart University',
            admin_id=None  # Temporarily None, will update after admin creation
        )
        db.session.add(shu_org)
        db.session.commit()  # Commit organization to get an ID

        # Create admin user for SHU
        shu_admin = User(
            email='admin@shu.edu',
            password=generate_password_hash('shuadminpass'),
            role='admin',
            first_name='SHU',
            last_name='Admin',
            organization_id=shu_org.id
        )
        db.session.add(shu_admin)
        db.session.commit()  # Commit admin to get an ID

        # Update organization with admin ID
        shu_org.admin_id = shu_admin.id
        db.session.commit()

        # Create regular user for SHU
        shu_user = User(
            email='user@shu.edu',
            password=generate_password_hash('shuuserpass'),
            role='user',
            first_name='SHU',
            last_name='User',
            organization_id=shu_org.id
        )
        db.session.add(shu_user)
        db.session.commit()

        print("Database populated with sysadmin, SHU organization, admin, and user!")

if __name__ == '__main__':
    populate_db()