package com.tough.jukebox.authentication.model;

public class VaultResponse {

    private Data data = new Data();

    public Data getData() {
        return data;
    }

    public void setData(Data data) {
        this.data = data;
    }

    public static class Data {
        private TokenData data = new TokenData();

        public TokenData getData() {
            return data;
        }

        public void setData(TokenData data) {
            this.data = data;
        }

        public static class TokenData {
            private String access_token = "";
            private String refresh_token = "";

            public String getAccess_token() {
                return access_token;
            }

            public void setAccess_token(String access_token) {
                this.access_token = access_token;
            }

            public String getRefresh_token() {
                return refresh_token;
            }

            public void setRefresh_token(String refresh_token) {
                this.refresh_token = refresh_token;
            }
        }
    }
}
