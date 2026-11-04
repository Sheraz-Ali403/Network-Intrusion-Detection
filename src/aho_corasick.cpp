#include "aho_corasick.h"
#include <queue> //for BFS

using std::string;
using std::vector;
using std::queue;

node::node(char input) : letter(input), patternID(-1)
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

void AhoCorasick::insertUtil(node* cur, const string& word, size_t index, int id)
{
    if (word.length() == index) //base case
    {
        cur->patternID = id;
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

    insertUtil(child, word, index + 1, id); //using recursion for insertion
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

            if (child->failureLink->patternID > -1)
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

            if (state->patternID > -1) //check if we find a pattern;
            {
                positions.push_back({i, state->patternID});
            }

            //check if theres any output link to other patterns
            node* finds = state;

            while (finds->outputLink != nullptr) //for multiple implicit patterns
            {
                positions.push_back({i, finds->outputLink->patternID});
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
}

void AhoCorasick::buildTrie(const vector<string>& pattern)
{
    for (size_t i = 0; i < pattern.size(); i++)
    {
        if (pattern[i].empty()) continue; // guard clause for empty string
        insertUtil(root, pattern[i], 0, static_cast<int>(i));
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