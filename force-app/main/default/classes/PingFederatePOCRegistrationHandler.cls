/**
 * Registration Handler para Auth Provider Ping Federate.
 * Sem JIT - apenas matching de usuários existentes via sub do id_token.
 * O sub deve corresponder ao FederationIdentifier do User no Salesforce.
 *
 * O framework usa Third-Party Account Links; na primeira vez que o usuário loga,
 * não existe link. Sem link, o framework chama createUser. Retornando o User existente
 * (localizado por FederationIdentifier), o framework cria o link e permite o login.
 */
global class PingFederatePOCRegistrationHandler implements Auth.RegistrationHandler {

    global boolean canCreateUser(Auth.UserData data) {
        return true; // Precisa ser true para createUser ser chamado (buscar user existente)
    }

    global User createUser(Id portalId, Auth.UserData data) {
        String fedId = data.attributeMap != null ? data.attributeMap.get('sfdc_federationid') : null;
        if (String.isBlank(fedId)) {
            fedId = data.identifier;
        }
        if (String.isBlank(fedId)) {
            return null;
        }
        List<User> users = [
            SELECT Id, IsActive
            FROM User
            WHERE FederationIdentifier = :fedId.trim()
            LIMIT 1
        ];
        if (users.isEmpty() || !users[0].IsActive) {
            return null;
        }
        return users[0]; // Retorna user existente -> framework cria o Third-Party Account Link
    }

    global void updateUser(Id userId, Id portalId, Auth.UserData data) {
        User u = new User(Id = userId);
        if (String.isNotBlank(data.email)) {
            u.email = data.email;
        }
        if (String.isNotBlank(data.lastName)) {
            u.lastName = data.lastName;
        }
        if (String.isNotBlank(data.firstName)) {
            u.firstName = data.firstName;
        }
        update u;
    }
}
