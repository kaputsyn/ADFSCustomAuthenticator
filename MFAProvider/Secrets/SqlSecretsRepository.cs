using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MFAProvider.Secrets
{
    public class SqlSecretsRepository
    {
        private static readonly string connstr = "Data Source=s-kv-test01-s01;Initial Catalog=MFA;Integrated Security=true;";
        public static async Task<string> GetSecret(string upn)
        {
            string sql = "SELECT [secret] FROM [dbo].[Secrets] where upn = @upn";
            using (SqlConnection connection = new SqlConnection(connstr))
            {
                using (var cmd = new SqlCommand(sql, connection))
                {
                    cmd.Parameters.AddWithValue("@upn", upn);
                    connection.Open();
                    // Создаем объект DataAdapter
                    SqlDataAdapter adapter = new SqlDataAdapter(cmd);
                    // Создаем объект Dataset
                    DataSet ds = new DataSet();
                    // Заполняем Dataset
                    adapter.Fill(ds);

                    if (ds.Tables == null
                        || ds.Tables.Count == 0
                        || ds.Tables[0].Columns.Count < 1)

                    {
                        throw new Exception("Invalid database response");
                    }
                    if (ds.Tables[0].Rows.Count == 0)
                    {
                        return null;
                    }

                    var value = ds.Tables[0].Rows[0][0];
                    if (value == DBNull.Value)
                    {
                        return null;
                    }

                    return (string)value;
                }
            }
        }


        public static async Task PutSecret(string upn, string secret)
        {
            string sql = @"MERGE [dbo].[Secrets] t 
                        USING(VALUES(@upn, @secret)) as s(upn, [secret])
                    ON(s.upn = t.upn)
                    WHEN MATCHED
                        THEN UPDATE SET
                            t.[secret] = s.[secret]
                    WHEN NOT MATCHED BY TARGET
                        THEN INSERT([upn], [secret])
                             VALUES(s.[upn], s.[secret]);";
            using (SqlConnection connection = new SqlConnection(connstr))
            {
                using (var cmd = new SqlCommand(sql, connection))
                {
                    cmd.Parameters.AddWithValue("@upn", upn);
                    cmd.Parameters.AddWithValue("@secret", secret);

                    connection.Open();

                    cmd.ExecuteNonQuery();
                }
            }
        }

    }
}
