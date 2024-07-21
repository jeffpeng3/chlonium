using System.Collections.Generic;
using System.Text;

namespace ChloniumUI
{
    class Item { }

    class Cookie : Item
    {
        public Dictionary<string, object> cookieValues = new Dictionary<string, object>();
        public byte[] decrypted_value;
    }

    class Login : Item
    {
        public string origin_url;
        public string action_url;
        public string username_element;
        public string username_value;
        public string password_element;
        public byte[] password_value;
        public string submit_element;
        public string signon_realm;
        public int preferred;
        public int date_created;
        public int blacklisted_by_user;
        public int scheme;
        public int password_type;
        public int times_used;
        public byte[] form_data;
        public int date_synced;
        public string display_name;
        public string icon_url;
        public string federation_url;
        public int skip_zero_click;
        public int generation_upload_status;
        public byte[] possible_username_pairs;
        public int id;
        public int date_last_used;
        public byte[] moving_blocked_for;
        public byte[] decrypted_password_value;

        public override string ToString()
        {
            return $"{origin_url},{username_value},{Encoding.UTF8.GetString(decrypted_password_value)}";
        }
    }
}
