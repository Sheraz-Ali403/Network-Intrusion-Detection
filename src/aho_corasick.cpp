#include "aho_corasick.h"
#include <queue> //for BFS
#include <fstream> //for file opening
#include <sstream> //for string parsing

using std::string;
using std::vector;
using std::queue;
using std::ifstream;
using std::ofstream;
using std::stringstream;
using std::getline;

node::node(char input) : letter(input), info(NULL)
{
    failureLink = nullptr;
    outputLink = nullptr;
    for (int i = 0; i < 256; i++)
    {
        children[i] = nullptr;
    }
}

AhoCorasick::AhoCorasick()
{
    root = new node('\0');
    root->failureLink = root; //root is depth 0, whose fail link is root
}

AhoCorasick::~AhoCorasick()
{
    destroy(root);
}

uint8_t AhoCorasick::lower(char c) //turn all letters to lower
{
    if (c >= 'A' && c <= 'Z') return c + 32;   // 'A'(65) to 'a'(97)
    return c;
}

void AhoCorasick::insertUtil(node* cur, const string& word, size_t index, patternInfo& pInfo)
{
    if (word.length() == index) // base case
    {
        cur->info = &pInfo; // Assign address directly
        return;
    }

    node* child;

    uint8_t i = lower(word[index]); //for correct index storing

    if (cur->children[i] != nullptr) // letter is present
    {
        child = cur->children[i];
    }
    else // letter is absent
    {
        child = new node(word[index]);
        cur->children[i] = child;
    }

    insertUtil(child, word, index + 1, pInfo); //using recursion for insertion
}

void AhoCorasick::buildFailAndOutputLinkUtil()
{
    queue<node*> q; //using BFS to create fail link for every node

    for (int i = 0; i < 256; i++) //the depth-1 fail link are always root itself, depth-0 is root btw
    {
        if (root->children[i])
        {
            root->children[i]->failureLink = root;
            q.push(root->children[i]);
        }
    }

    while (!q.empty()) //runs until every fail link is established
    {
        node* curr = q.front();  //the parent node for traversing
        q.pop();

        for (int i = 0; i < 256; i++)
        {
            node* child = curr->children[i]; //the child node is whose fail link we're going to create

            if (!child) continue; //if child doesn't exist skip this loop

            node* failTravel = curr->failureLink; //node for travelling the fail link

            while (failTravel != root && failTravel->children[i] == nullptr)
            {
                //until we reach depth-0(root) or until we find node containing the proper child;
                failTravel = failTravel->failureLink;
            }

            if (failTravel == root && !root->children[i]) child->failureLink = root; //if we reach depth-0 and it doesn't have proper child
            else child->failureLink = failTravel->children[i];

            if (child->failureLink->info!=nullptr)
            {
                //if failurelink also ends a pattern, we put it as output link too
                child->outputLink = child->failureLink;
            }
            else
            {
                //otherwise we use next nearest outputlink;
                child->outputLink = child->failureLink->outputLink;
            }

            //one good thing to remember is outputLink will always point to a pattern ending node

            q.push(child); //so we can use it as parent node for it's children
        }
    }
}

vector<match> AhoCorasick::scanPatternUtil(const uint8_t* data, size_t len)
{
    node* state = root;
    vector<match> positions; //for storing the alerts positions and ID

    size_t i = 0;

    while (i < len)
    {
        size_t cha = lower(data[i]); //to align with the index of children

        if (state->children[cha] != nullptr) //if the child exist
        {
            i++;

            state = state->children[cha];

            if (state->info!=nullptr) //check if we find a pattern;
            {
                positions.push_back({i, state->info});
            }

            //check if theres any output link to other patterns
            node* finds = state;

            while (finds->outputLink != nullptr) //for multiple implicit patterns
            {
                if(finds->outputLink->info!=nullptr)
                {
                    positions.push_back({i, finds->outputLink->info});
                }
                finds = finds->outputLink;
            }
        }
        else if (state != root) //backtrack to failLink
        {
            state = state->failureLink;
        }
        else
        {
            i++;
        }
    }

    return positions;
}

void AhoCorasick::destroy(node* cur) //for destructor
{
    for (int i = 0; i < 256; i++)
    {
        if (cur->children[i])
        {
            destroy(cur->children[i]);
        }
    }

    delete cur;
};

void AhoCorasick::buildTrie(vector<patternInfo>& patterns)
{
    for (size_t i = 0; i < patterns.size(); i++)
    {
        if (patterns[i].pattern.empty()) continue; // guard clause for empty string
        insertUtil(root, patterns[i].pattern,0, patterns[i]);
    }
}

void AhoCorasick::buildFailAndOutputLink()
{
    buildFailAndOutputLinkUtil();
}

vector<match> AhoCorasick::scanPattern(const uint8_t* data, size_t len)
{
    return scanPatternUtil(data, len);
}

void AhoCorasick::openRules(vector<patternInfo>& patterns, const string& path)
{
    ifstream file(path);

    if(!file.is_open()) return;//file not open

    string line;
    while(getline(file,line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back(); //windows put \r at the end of text so to remove that
        if(line.empty()) continue; //if empty

        string name, pattern, severity;
        string id;

        stringstream ss(line);

        if (getline(ss, id, '|') && getline(ss, severity, '|') &&getline(ss, name, '|') &&getline(ss, pattern)) 
        {
            patternInfo p(name,stoi(id),severity,pattern);
            patterns.push_back(p);
        }
    }

    buildTrie(patterns);
    buildFailAndOutputLink();

}

void AhoCorasick::writeAlerts(const string& path, vector<match> alerts, const string& flow)
{
    ofstream file(path, std::ios::app);

    if(!file.is_open()) return;

    for(size_t i=0; i< alerts.size();i++)
    {
        if (alerts[i].info != nullptr)
        {
            file << "[ALERT] ID: " << alerts[i].info->id
                 << " | Name: " << alerts[i].info->name
                 << " | Severity: " << alerts[i].info->severity
                 << " | Pattern: " << alerts[i].info->pattern
                 << " | Offset: " << alerts[i].endOffset
                 << " | Flow: " << flow << "\n";
        }
    }
}