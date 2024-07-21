using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Windows;

namespace ChloniumUI
{
    internal class ExportMethods
    {
        public static List<Item> ExportCookies(byte[] keyBytes, string inputFile)
        {
            List<Item> items = new List<Item>();

            // initialize AES
            AesCrypto crypto = new AesCrypto(keyBytes);

            // open the Cookie db
            string cs = string.Format("Data Source={0};", inputFile);
            string stm = "SELECT * FROM cookies ORDER BY host_key;";
            SQLiteConnection con = new SQLiteConnection(cs);
            con.Open();

            SQLiteCommand cmd = new SQLiteCommand(stm, con);
            SQLiteDataReader reader = cmd.ExecuteReader();

            int exceptionsCount = 0;

            if (reader.HasRows)
            {
                bool ret = true;
                int errCount = 0;

                while (ret)
                {
                    byte[] encrypted_value;
                    try
                    {
                        ret = reader.Read();
                        encrypted_value = (byte[])reader["encrypted_value"];
                    }
                    catch
                    {
                        errCount++;

                        if (errCount > 3)
                        {
                            MessageBox.Show("Some cookies could not be imported.", "Warning");
                            break;
                        }

                        continue;
                    }

                    byte[] decrypted_value = null;

                    if (encrypted_value[0] == 'v' && encrypted_value[1] == '1' && encrypted_value[2] == '0')
                    {
                        try
                        {
                            decrypted_value = crypto.Decrypt(encrypted_value);
                        }
                        catch (Exception e)
                        {
                            if (exceptionsCount < 3)
                            {
                                MessageBox.Show(e.Message);
                                exceptionsCount++;
                            }
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: we could extract DPAPI keys too maybe
                        continue;
                    }

                    Cookie cookie = new Cookie();
                    cookie.decrypted_value = decrypted_value;

                    for(int idx=0; idx<reader.FieldCount; ++idx) {
                        cookie.cookieValues[reader.GetOriginalName(idx)] = reader[idx];
                    }      
                    
                    items.Add(cookie);
                }
            }
            else
            {
                Console.WriteLine("No rows found.");
            }

            try
            {
                reader.Close();
            }
            catch
            { }

            if (items.Count() == 0)
            {
                MessageBox.Show("No cookies were exported from specified input database!", "Error");
            }

            return items;
        }

        public static List<Item> ExportLogins(byte[] keyBytes, string inputFile)
        {
            List<Item> items = new List<Item>();

            // initialize AES
            AesCrypto crypto = new AesCrypto(keyBytes);

            // open the Cookie db
            string cs = string.Format("Data Source={0};", inputFile);
            string stm = "SELECT * FROM logins ORDER BY origin_url;";
            SQLiteConnection con = new SQLiteConnection(cs);
            con.Open();

            SQLiteCommand cmd = new SQLiteCommand(stm, con);
            SQLiteDataReader reader = cmd.ExecuteReader();

            int exceptionsCount = 0;

            int originUrlId = reader.GetOrdinal("origin_url");
            int actionUrlId = reader.GetOrdinal("action_url");
            int usernameElementId = reader.GetOrdinal("username_element");
            int usernameValueId = reader.GetOrdinal("username_value");
            int passwordElementId = reader.GetOrdinal("password_element");
            int submitElement = reader.GetOrdinal("submit_element");
            int signonRealmId = reader.GetOrdinal("signon_realm");
            int preferredId = reader.GetOrdinal("preferred");
            int dateCreatedId = reader.GetOrdinal("date_created");
            int blacklistedByUserId = reader.GetOrdinal("blacklisted_by_user");
            int schemeId = reader.GetOrdinal("scheme");
            int passwordTypeId = reader.GetOrdinal("password_type");
            int timesUsedId = reader.GetOrdinal("times_used");
            int dateSyncedId = reader.GetOrdinal("date_synced");
            int displayNameId = reader.GetOrdinal("display_name");
            int iconUrl = reader.GetOrdinal("icon_url");
            int federationUrlId = reader.GetOrdinal("federation_url");
            int skipZeroClickId = reader.GetOrdinal("skip_zero_click");
            int generationUploadStatusId = reader.GetOrdinal("generation_upload_status");
            int idId = reader.GetOrdinal("id");
            int dateLastUsedId = reader.GetOrdinal("date_last_used");

            if (reader.HasRows)
            {
                bool ret = true;
                int errCount = 0;

                while (ret)
                {
                    byte[] encrypted_value;
                    try
                    {
                        ret = reader.Read();
                        encrypted_value = (byte[])reader["password_value"];
                    }
                    catch
                    {
                        errCount++;

                        if (errCount > 3)
                        {
                            MessageBox.Show("Some logins could not be imported.", "Warning");
                            break;
                        }

                        continue;
                    }

                    byte[] decrypted_value = null;

                    if (encrypted_value[0] == 'v' && encrypted_value[1] == '1' && encrypted_value[2] == '0')
                    {
                        try
                        {
                            decrypted_value = crypto.Decrypt(encrypted_value);
                        }
                        catch (Exception e)
                        {
                            if (exceptionsCount < 3)
                            {
                                MessageBox.Show(e.Message);
                                exceptionsCount++;
                            }
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: we could extract DPAPI keys too maybe
                        continue;
                    }

                    Login login = new Login
                    {
                        origin_url = originUrlId == -1 ? "" : reader.GetString(originUrlId),
                        action_url = actionUrlId == -1 ? "" : reader.GetString(actionUrlId),
                        username_element = usernameElementId == -1 ? "" : reader.GetString(usernameElementId),
                        username_value = usernameValueId == -1 ? "" : reader.GetString(usernameValueId),
                        password_element = passwordElementId == -1 ? "" : reader.GetString(passwordElementId),
                        password_value = encrypted_value,
                        submit_element = submitElement == -1 ? "" : reader.GetString(submitElement),
                        signon_realm = signonRealmId == -1 ? "" : reader.GetString(signonRealmId),
                        preferred = preferredId == -1 ? 0 : reader.GetInt32(preferredId),
                        date_created = dateCreatedId == -1 ? 0 : reader.GetInt32(dateCreatedId),
                        blacklisted_by_user = blacklistedByUserId == -1 ? 0 : reader.GetInt32(blacklistedByUserId),
                        scheme = schemeId == -1 ? 0 : reader.GetInt32(schemeId),
                        password_type = passwordTypeId == -1 ? 0 : reader.GetInt32(passwordTypeId),
                        times_used = timesUsedId == -1 ? 0 : reader.GetInt32(timesUsedId),
                        form_data = Convert.IsDBNull(reader["form_data"]) ? null : (byte[])reader["form_data"],
                        date_synced = dateSyncedId == -1 ? 0 : reader.GetInt32(dateSyncedId),
                        display_name = displayNameId == -1 ? "" : reader.GetString(displayNameId),
                        icon_url = iconUrl == -1 ? "" : reader.GetString(iconUrl),
                        federation_url = federationUrlId == -1 ? "" : reader.GetString(federationUrlId),
                        skip_zero_click = skipZeroClickId == -1 ? 0 : reader.GetInt32(skipZeroClickId),
                        generation_upload_status = generationUploadStatusId == -1 ? 0 : reader.GetInt32(generationUploadStatusId),
                        possible_username_pairs = Convert.IsDBNull(reader["possible_username_pairs"]) ? null : (byte[])reader["possible_username_pairs"],
                        id = idId == -1 ? 0 : reader.GetInt32(idId),
                        date_last_used = dateLastUsedId == -1 ? 0 : reader.GetInt32(dateLastUsedId),
                        moving_blocked_for = Convert.IsDBNull(reader["moving_blocked_for"]) ? null : (byte[])reader["moving_blocked_for"],
                        decrypted_password_value = decrypted_value
                    };
                    items.Add(login);
                }
            }
            else
            {
                Console.WriteLine("No rows found.");
            }
            reader.Close();

            if (items.Count() == 0)
            {
                MessageBox.Show("No logins were exported from specified input database!", "Error");
            }

            return items;
        }
    }
}
