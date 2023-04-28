class HunterQuery:
    def __init__(self):
        self.query = "" 
        self.results = []
        self.result_count = 0
    
    def show_summary(self):
        logger.warn("Not implemented!")

    def show_details(self):
        logger.warn("Not implemented!")


class ShortestPathFromAllQuery(HunterQuery):

    def __init__(self):
        self.query = '''
MATCH (u)-[:MemberOf*1]->(g:Group) 
    WHERE g.objectid =~ "(?i)(.*-S-1-5-9)|(S-1-5-(.*-(512|516|519)|(9)|-32-544))" 
    WITH COLLECT(u) as Admins


MATCH p=shortestPath((n)-[rels:AddKeyCredentialLink|AddMember|AdminTo|AllExtendedRights|AllowedToAct|ForceChangePassword|GenericAll|GenericWrite|GetChanges|GetChangesAll|GetChangesInFilteredSet|MemberOf|Owns|WriteAccountRestrictions|WriteDacl|WriteOwner|CanRDP|HasSession*1..]->(c:Domain)) 

    WHERE not n in Admins
AND (n:User or n:Computer or n:Group or n:Domain) 
AND (not n.objectid = c.objectid) 
WITH [r in rels | [STARTNODE(r).name, type(r), ENDNODE(r).name]] as steps, length(p) as pathLength
RETURN pathLength, steps ORDER BY pathLength DESC
    '''

    def show_summary(self):
        pass 
        
    def show_details(self):
        for result in results:
            steps = result["steps"]
            print(f'{steps[0][0]} is {result["pathLength"]} steps away from {steps[-1][2]}.')
            path = f'{steps[0][0]} -> {steps[0][1]} -> {steps[0][2]}'
            for step in steps[1:]:
                path += f' -> {step[1]} -> {step[2]}'
            print(f'{path}\n')
