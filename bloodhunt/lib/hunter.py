import csv
from pathlib import Path
from neo4j import GraphDatabase
from enum import Enum
from bloodhunt.logger import logger


HQL_KEY_QUERY = 'query'
HQL_KEY_ADVICE = 'advice'
HQL_KEY_FILENAME = 'output_file'
HQL_KEY_FIELDNAMES = 'fieldnames'

class HunterQueryList(Enum):
    ASREP_ROASTABLE_USERS = {
        HQL_KEY_QUERY: 'MATCH (u:User {dontreqpreauth: true}) WHERE u.enabled RETURN u.name AS AS_REP_Roastable_User',
        HQL_KEY_ADVICE: 'ASREP roast these accounts to gain access to the network',
        HQL_KEY_FILENAME: 'asrep_roastable_users.csv'
        # HQL_KEY_FIELDNAMES: ['Username']
    }

    KERBEROASTABLE_USERS = {
        HQL_KEY_QUERY: 'MATCH (n:User) WHERE n.enabled and not n.name =~ "KRBTGT@.*" AND n.hasspn=true RETURN n.name AS Kerberoastable_User',
        HQL_KEY_ADVICE: 'Kerberoast the users to escalate, or use a tool like RITM to gain access to the network',
        HQL_KEY_FILENAME: 'kerberoastable_users.csv'
        # HQL_KEY_FIELDNAMES: ['Username']
    }

    SHORTEST_PATH_FROM_ALL = {
        HQL_KEY_QUERY: 'MATCH (u)-[:MemberOf*1]->(g:Group) WHERE g.objectid =~ "(?i)(.*-S-1-5-9)|(S-1-5-(.*-(512|516|519)|(9)|-32-544))" WITH COLLECT(u) as Admins MATCH p=shortestPath((n)-[rels:AddKeyCredentialLink|AddMember|AllowedToDelegate|AdminTo|AllExtendedRights|AllowedToAct|ForceChangePassword|GenericAll|GenericWrite|GetChanges|GetChangesAll|GetChangesInFilteredSet|MemberOf|Owns|WriteAccountRestrictions|WriteDacl|WriteOwner|CanRDP|HasSession*1..]->(c:Domain)) WHERE not n in Admins AND (n:User or n:Computer or n:Group or n:Domain) AND (not n.objectid = c.objectid) WITH [r in rels | [STARTNODE(r).name, type(r), ENDNODE(r).name]] as steps, length(p) as pathLength RETURN pathLength, steps ORDER BY pathLength DESC',
        HQL_KEY_ADVICE: 'Analyze this list of starting nodes compared to owned users to find paths that are available.',
        HQL_KEY_FILENAME: 'shortest_path_from_all.csv'
        # HQL_KEY_FIELDNAMES: ["Path Length", "Path Steps"]
    }

    ACL_OWNERSHIP = {
        HQL_KEY_QUERY: 'MATCH (u:User)-[r1:MemberOf*..]->(g:Group)-[r2:GenericAll|Owns|WriteOwner|WriteDacl]->(o) WHERE u.enabled RETURN DISTINCT(u.name) as User, count(o) as ACLOwnership ORDER BY COUNT(o) DESC', 
        HQL_KEY_ADVICE: 'Analyze this list of starting nodes compared to owned users to find paths that are available.',
        HQL_KEY_FILENAME: 'acl_ownership.csv'
    }

    ADCS_AVAILABLE = {
        HQL_KEY_QUERY: 'MATCH (g:Group) WHERE g.name =~ "(?i)(CERT PUBLISHERS@.*)" RETURN g.name as Cert_Group',
        HQL_KEY_ADVICE: 'Investigate ADCS attack vectors such as ESC1, ESC2, ESC4, etc...',
        HQL_KEY_FILENAME: 'adcs_available.csv'
    }

    ACTIVE_UNSUPPORTED_OS = {
        HQL_KEY_QUERY: 'MATCH (n:Computer) WHERE n.lastlogontimestamp IS NOT NULL MATCH (n) WITH n, datetime({epochSeconds: toInteger(n.lastlogontimestamp)}) as LastLogon WHERE n.enabled AND n.operatingsystem =~ "(?i).*(2000|2003|2008|xp|vista|7|me).*" AND n.lastlogontimestamp IS NOT NULL AND LastLogon.epochseconds > datetime().epochseconds - (90 * 86400) AND n.enabled RETURN n.name as Computer, n.operatingsystem as Operating_System, LastLogon', #, duration.inDays(datetime(),LastLogon) as daysSinceLogon ORDER by daysSinceLogon ASC',
        HQL_KEY_ADVICE: 'Computers are active on the network with unsupported OS. Review scan data for vulnerabilities and highlight this to client.',
        HQL_KEY_FILENAME: 'active_unsupported_os.csv'
    }

    UNCONSTRAINED_DELEGATION = {
        HQL_KEY_QUERY: 'MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH "-516" WITH COLLECT(c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2.name as Computer',
        HQL_KEY_ADVICE: 'If access to these machines are controlled, use the printerbug or PetitPotam to coerce authentication from a DC',
        HQL_KEY_FILENAME: 'unconstrained_delegation.csv'
    }

    CONSTRAINED_DELEGATION = {
        HQL_KEY_QUERY: 'MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name as Computer, c.allowedtodelegate as AllowedToDelegateTo',
        HQL_KEY_ADVICE: 'If access to one of these computers is contained, users can laterally move to other machines via constrained delegation',
        HQL_KEY_FILENAME: 'constrained_delegation.csv'
    }

    GPO_CONTROL_BY_NON_ADMINS = {
        HQL_KEY_QUERY: 'MATCH (u)-[:MemberOf*1]->(g:Group) WHERE (g.objectid =~ "(?i)(.*-S-1-5-9)|(S-1-5-(.*-(512|516|519)|(9)|-32-544))" OR u.objectid =~ "(?i)(.*-S-1-5-9)|(S-1-5-(.*-(512|516|519)|(9)|-32-544))") AND (u:User or u:Group or u:Computer) WITH COLLECT(u) AS Admins MATCH p=(n)-[rels:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1]->(g:GPO) WHERE not n in Admins WITH [r in rels | [STARTNODE(r).name, type(r), ENDNODE(r).name]] as steps RETURN steps',
        HQL_KEY_ADVICE: 'These non-admin entities have direct control over GPO objects in the domain. Extreme caution should be taking in abusing GPO objects',
        HQL_KEY_FILENAME: 'gpo_control_by_non_admins.csv'
    }

    VPN_USERS = {
        HQL_KEY_QUERY: "Match (u:User)-[:MemberOf]->(g:Group) WHERE toUPPER (g.name) CONTAINS 'VPN' return u.name as User, g.name as MemberOfGroup",
        HQL_KEY_ADVICE: "Spraying this list of users may net remote access via a VPN",
        HQL_KEY_FILENAME: 'vpn_users.csv'
    }

    USERS_IN_SERVER_GROUPS = {
        HQL_KEY_QUERY: "MATCH (u:User)-[:MemberOf]->(g:Group) WHERE TOUPPER(g.name) CONTAINS 'SERVER' return u.name as User, g.name as MemberOfGroup",
        HQL_KEY_ADVICE: "Users have been placed into groups meant for servers. This should be investigated",
        HQL_KEY_FILENAME: 'users_in_server_groups.csv'
    }

    COMPUTERS_IN_USER_GROUPS = {
        HQL_KEY_QUERY: "MATCH (c:Computer)-[:MemberOf]->(g:Group) WHERE TOUPPER(g.name) CONTAINS 'USERS' return c.name as Computer, g.name as MemberOfGroup",
        HQL_KEY_ADVICE: "Computers have been placed into groups meant for users. This should be investigated",
        HQL_KEY_FILENAME: 'computers_in_user_groups.csv'
    }


class Hunter:

    ALL_QUERIES = list(HunterQueryList)
    DEFAULT_RESULT_LIMIT = 10


    def __init__(self, uri="neo4j://127.0.0.1", user="neo4j", password="neo4j",
        filtered_edges=[], result_limit=None, output_directory='.'):
        logger.info(f'Connecting to {uri}')
        self.uri = uri
        self.user = user 
        self.password = password 
        if filtered_edges:
            self.filtered_edges = filtered_edges
        else:
            self.filtered_edges = []
        self.result_limit = result_limit
        self.output_directory = output_directory
        self.driver = GraphDatabase.driver(uri, auth=(user,password))
        self.driver.verify_connectivity()


    def close(self):
        self.driver.close()


    def _remove_filtered_edges(self, query):
        for edge in self.filtered_edges:
            query = query.replace(edge, '')
            query = query.replace('|*', '*')
            query = query.replace(',,', ',')
            query = query.replace('||', '|')
            logger.debug(f"Removing filtered edge {edge} from query...")

        return query


    def _add_query_limit(self, query):
        if self.result_limit:
            query = f'{query} LIMIT {self.result_limit}'
            logger.debug(f'Limiting query results to {self.result_limit}')
        return query


    def _execute_query(self, query:HunterQueryList):
        query = query.value[HQL_KEY_QUERY]
        with self.driver.session() as session:
            query = self._remove_filtered_edges(query)
            query = self._add_query_limit(query)
            results = session.run(query)
            return results.data()


    def _write_csv(self, filename, headers, data):
        with open(Path(self.output_directory) / Path(filename), 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            if len(headers) > 0:
                writer.writeheader()
            for result in data:
                writer.writerow(result)


    def _write_results(self, query:HunterQueryList, results):
        fieldnames = []
        data = []

        if query == HunterQueryList.SHORTEST_PATH_FROM_ALL:
            fieldnames, data = self.show_shortest_paths_from_all(results)
        elif query == HunterQueryList.GPO_CONTROL_BY_NON_ADMINS:
            fieldnames, data = self.show_gpo_control_by_non_admins(results)
        else:
            fieldnames = list(results[0].keys())
            data = results

        self._write_csv(query.value[HQL_KEY_FILENAME], fieldnames, data) 


    def get_summary(self):
        for query in HunterQueryList:
            logger.info(f'Running {query}...')
            results = self._execute_query(query)
            
            if len(results) > 0:
                self._write_results(query, results)
                logger.info(f'{len(results)} results stored in {query.value[HQL_KEY_FILENAME]}!')
                logger.info(f'{query.value[HQL_KEY_ADVICE]}')
            else:
                logger.info(f'No results found')
            
            print()

    
    def show_gpo_control_by_non_admins(self, results):
        paths = []
        fieldnames = ["Path Steps"]

        for result in results:
            steps = result["steps"]
            path = f'{steps[0][0]} -> {steps[0][1]} -> {steps[0][2]}'
            for step in steps[1:]:
                path += f' -> {step[1]} -> {step[2]}'
            paths.append({
                'Path Steps': path,
            })
        
        return fieldnames, paths


    def show_shortest_paths_from_all(self, results):
        result_count = len(results)
        paths = []
        fieldnames = ["Path Length", "Path Steps"]
        
        for result in results:
            steps = result["steps"]
            # print(f'{steps[0][0]} is {result["pathLength"]} steps away from {steps[-1][2]}.')
            path = f'{steps[0][0]} -> {steps[0][1]} -> {steps[0][2]}'
            for step in steps[1:]:
                path += f' -> {step[1]} -> {step[2]}'
            paths.append({
                'Path Steps': path,
                'Path Length': len(steps)
            })

    
        return fieldnames, paths
        #logger.info(f"{result_count} entities have paths to domain ownership")

        
