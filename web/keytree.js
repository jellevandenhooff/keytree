var React = require('react/addons');

var $ = require('jquery');
var d3 = require('d3');
d3.tip = require('d3-tip');
var _ = require('lodash');
var crypto = require('./crypto');

var downloadJson = function(url) {
  return Promise.resolve($.ajax(url, {dataType: 'json'}));
}

function D3Wrapper(d3Class) {
  return React.createClass({
    componentDidMount: function() {
      var el = this.getDOMNode();
      this.d3 = new d3Class(el, this.props);
    },

    componentDidUpdate: function() {
      this.d3.update(this.props);
    },

    componentWillUnmount: function() {
      var el = this.getDOMNode();
      this.d3.destroy(el);
    },

    render: function() {
      return (
        <div></div>
      );
    }
  });
}

function Tree(el, props) {
  var width = 640,
      height = 40;

  var diagonal = d3.svg.diagonal();

  var svg = d3.select(el).append("svg")
      .attr("width", width)
      .attr("height", height)
    .append("g")
      .attr("transform", "translate(10,10)");

  var tip = d3.tip()
    .attr('class', 'd3-tip')
    .html(function(d) { return d.label; })
    .offset([-12, 0])

  svg.call(tip);

  var node = svg.selectAll(".node"),
      link = svg.selectAll(".link");

  var duration = 750;

  downloadTree().then((root) => this.update(root));

  var origin;

  var openNow;

  this.update = function(root) {
    root.parent = root;

    var nodes = [];

    var maxDepth = 0;

    var collect = function(node, depth) {
      if (!node) {
        return;
      }
      if (depth > maxDepth) {
        maxDepth = depth;
      }
      nodes.push(node);
      if (node.baseChildren) {
        if (depth % 5 == 0 && !node.open && depth > 0) {
          node.children = [];
          node.flippable = true;
        } else {
          node.children = node.baseChildren;
          collect(node.children[0], depth+1);
          collect(node.children[1], depth+1);
        }
      }
    };

    collect(root, 0);

    var treeHeight = maxDepth * 40;

    var tree = d3.layout.tree()
        .size([width - 20, treeHeight]);


    // Recompute the layout and data join.
    node = node.data(tree.nodes(root), (d) => d.id);
    link = link.data(tree.links(nodes), (d) => d.source.id + "-" + d.target.id);

    var icon = (d) => {
      /* if (d.label === "nil") {
        return "\uf10c";
      } else */ if (d.baseChildren && !d.open && d.flippable) {
        return "\uf055";
      } else if (d.baseChildren && d.open) {
        return "\uf056";
      } else {
        return "\uf111";
      }
    };

    // Add entering nodes in the parent’s old position.
    var gs = node.enter()
        .append("g")
        .attr("class", "node")
        .attr("transform", (d) => origin ? ("translate(" + origin.x + "," + origin.y + ")") : 
            
            ("translate(" + d.x + "," + d.y + ")"));

    node.exit().remove();

    gs
        .append("circle")
        .attr("r", 8)
        .attr("cx", 0)
        .attr("cy", 0)
        .attr("fill", "#fff")

    
    node.select("text").text(icon);
        
    gs
        .append("text")
        .attr("class", (d) => d.label === "nil" ? "nil" : "")
        .text(icon)
        /* .attr("r", 4) */
        .attr("text-anchor", "middle")
        .on("mouseover", tip.show)
        .on("mouseout", tip.hide)
        .on("click", (d) => {
          if (d.flippable && !d.open) {
            d.open = true;
            if (openNow) {
              openNow.open = false;
            }
            openNow = d;
          } else if (d.flippable && d.open) {
            d.open = false;
            openNow = undefined;
          }
          origin = {x: d.x, y: d.y};
          this.update(root);
        });


    // Add entering links in the parent’s old position.
    link.enter().insert("path", "g")
        .attr("class", (d) => d.target.label === "nil" ? "nil link" : "link")
        .attr("d", function(d) {
          if (origin) {
            return diagonal({source: origin, target: origin});
          }
        });

    link.exit().remove();

    // Transition nodes and links to their new positions.
    var t = svg.transition()
        .duration(duration);

    d3.select(el).transition().duration(duration).select("svg").attr("height", treeHeight+20);

    t.selectAll("path")
        .attr("d", diagonal);

    t.selectAll(".node")
        .attr("transform", (d) => "translate(" + d.x + "," + d.y + ")");
        /*.attr("x", (d) => d.px = d.x)
        .attr("y", (d) => d.py = d.y);*/
  }
}

var D3Tree = D3Wrapper(Tree);

function timeConverter(unix){
  return (new Date(unix*1000)).toLocaleString();
}

var knownKeys = {
  "keytree.io": "ed25519-pub(26wj522ncyprkc0t9yr1e1cz2szempbddkay02qqqxqkjnkbnygg)",
  "Jelle's laptop": "ed25519-pub(xmmqz7cvgdd9ewa79vw9cw9qvemyd4x3zsaftacc2jqqm4nfzw20)"
};

var humanizeKey = function(key) {
  for (name of Object.keys(knownKeys)) {
    if (knownKeys[name] === key) {
      return name;
    }
  }
  return key;
};

var LookupDisplayer = React.createClass({
  getInitialState: function() {
    return {};
  },
  render: function() {
    /* {timeConverter(this.props.lookup.SignedTrieLookups[publicKey].SignedRoot.Root.Timestamp)} */
    return (
      <div>
        <pre>{JSON.stringify(this.props.lookup.Entry, null, "  ")}</pre>
        <h4>Authenticated by:</h4>
        <ul className="list-unstyled">
          {Object.keys(this.props.lookup.SignedTrieLookups).map((publicKey) =>
            <li key={publicKey}><span style={{color: "green"}}><i className="fa fa-check"></i></span> {humanizeKey(publicKey)}</li>)}
        </ul>
      </div>
    );
  }
});

var Lookup = React.createClass({
  mixins: [React.addons.LinkedStateMixin],
  fetch: async function(name) {
    this.setState({loading: true});
    try {
      var data = await downloadJson("/keytree/lookup?name=" + name);
      this.setState({loading: false, result: data});
    } catch (e) {
      this.setState({result: undefined, loading: false});
    }
  },
  componentDidMount: function() {
    window.lookup = this;
  },
  getInitialState: function() {
    return {name: '', loading: false, result: undefined};
  },
  handleLookup: function(e) {
    e.preventDefault();
    this.fetch(this.state.name);
  },
  render: function() {
    return (
      <div>
        <h1>Lookup</h1>
        <form className="input-group" onSubmit={this.handleLookup}>
          <input type="text" className="form-control" valueLink={this.linkState('name')} />
          <span className="input-group-btn">
            <button id="lookup-submit-btn" className="btn btn-primary" type="submit" 
                disabled={this.state.loading ? 'disabled' : null}>
                {this.state.loading ? 'Loading...' : 'Lookup'}
            </button>
          </span>
        </form>
        {this.state.result ? <LookupDisplayer lookup={this.state.result} /> : null}
      </div>
    );
  }
});

var Update = React.createClass({
  mixins: [React.addons.LinkedStateMixin],
  fetch: async function(name) {
    this.setState({loading: true, newKeys: {}});
    try {
      var data = await downloadJson("/keytree/lookup?name=" + name);
      this.setState({loading: false, oldKeys: data.Entry.Keys, loaded: true, newKeyName: ''});
    } catch (e) {
      this.setState({oldKeys: undefined, loading: false, loaded: true});
    }
  },
  getInitialState: function() {
    return {name: '', loading: false, oldKeys: undefined, newKeys: {}, loaded: false};
  },
  handleLookup: function(e) {
    e.preventDefault();
    this.fetch(this.state.name);
  },
  addKey: function(e) {
    e.preventDefault();
    this.state.newKeys[this.state.newKeyName] = 'hello!';
    this.setState({newKeys: this.state.newKeys, newKeyName: ''});
  },
  render: function() {
    var editor;

    if (this.state.loaded) {
      var oldKeys = this.state.oldKeys || {};
      var newKeys = this.state.newKeys || {};
      
      var allKeys = Object.keys(oldKeys).concat(Object.keys(newKeys));
      allKeys.sort();
      allKeys = _.uniq(allKeys);

      editor = (
        <div>
          {allKeys.map((key) => <p>{key}</p>)}
          <form className="input-group" onSubmit={this.addKey}>
            <input type="text" className="form-control" valueLink={this.linkState('newKeyName')} />
            <span className="input-group-btn">
              <button id="lookup-submit-btn" className="btn btn-primary" type="submit">Add key</button>
            </span>
          </form>
        </div>
      );
    }

    return (
      <div>
        <h1>Update</h1>
        <form className="input-group" onSubmit={this.handleLookup}>
          <input type="text" className="form-control" valueLink={this.linkState('name')} />
          <span className="input-group-btn">
            <button id="lookup-submit-btn" className="btn btn-primary" type="submit" 
                disabled={this.state.loading ? 'disabled' : null}>
                {this.state.loading ? 'Loading...' : 'Lookup'}
            </button>
          </span>
        </form>
        {editor}
      </div>
    );
  }
});

function shorten(s) {
  return s.substring(0, 20) + "...";
}

var nilHash = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

var counter = 0;

var downloadNode = async function(hash) {
  if (hash === nilHash) {
    return undefined;
  }

  var data = await downloadJson("/keytree/trienode?hash=" + hash);

  if (data === null) {
    return data;
  }

  if (data.Leaf) {
    var entryData = await downloadJson("/keytree/lookup?hash=" + data.Leaf.NameHash);
    var name = entryData.Entry.Name;

    return {
      id: hash,
      label: "<span>" + shorten(hash) + "</span><br><span>" + name + "</span>",
      nameHash: data.Leaf.NameHash,
      entryHash: data.Leaf.EntryHash
    };
  } else {
    var promises = [downloadNode(data.ChildHashes[0]), downloadNode(data.ChildHashes[1])];
    var children = _.map([await promises[0], await promises[1]], (node) => node ? node : {id: '' + counter++, label: 'nil'});

    return {
      id: hash,
      label: "<span>" + shorten(hash) + "</span>",
      baseChildren: children
    };
  }
}

var downloadTree = async function() {
  var data = await downloadJson("/keytree/root");
  return await downloadNode(data.Root.RootHash);
}

var Browser = React.createClass({
  fetch: async function(after) {
    this.setState({loading: true});
    try {
      var data;
      if (after !== undefined) {
        data = await downloadJson("/keytree/browse?name=" + after);
      } else {
        data = await downloadJson("/keytree/browse");
      }
      if (data === null) {
        if (after !== undefined) {
          this.fetch();
        }
        return;
      }
      this.setState({loading: false, records: data});
    } catch (e) {
      this.setState({loading: false});
    }
  },
  componentDidMount: function() {
    this.fetch();
  },
  getInitialState: function() {
    return {records: [], loading: true};
  },
  handleNext: function(e) {
    e.preventDefault();
    var after = undefined;
    if (this.state.records.length > 0) {
      after = this.state.records[this.state.records.length - 1].Name;
    }
    this.fetch(after);
  },
  handleClick: function(name, e) {
    e.preventDefault();
    window.lookup.setState({name: name});
    window.lookup.fetch(name);
  },
  render: function() {
    var list = (
      <ul className="list-unstyled">
        {this.state.records.map((record) => 
          <li key={record.Name}><a href="#" onClick={this.handleClick.bind(this, record.Name)}>{record.Name}</a></li>)}
      </ul>
    );

    return (
      <div>
        <h1>Browse</h1>
        {list}
        {this.state.loading ?
          <span>Loading...</span> : 
          <a href="#" onClick={this.handleNext}>More...</a>}
      </div>
    );
  }
});

var Tree = React.createClass({
  /* fetch: async function(after) {
    this.setState({loading: true});
    try {
      var data = await downloadJson("/keytree/root");
      this.setState({loading: false, root: data});
    } catch (e) {
      this.setState({loading: false});
    }
  }, */
  componentDidMount: function() {
    /* this.fetch(); */
  },
  getInitialState: function() {
    // return {root: undefined, loading: true};
    return {};
  },
  render: function() {
    return (
      <div>
        <h1>Tree</h1>
        <D3Tree />
      </div>
    );
    /*
    {this.state.loading ?
      <span>Loading...</span> : 
      <pre>{JSON.stringify(this.state.root, null, "  ")}</pre>}
    */
  }
});

var App = React.createClass({
  render: function() {
    // Client side-verification
    return (
      <div>
        <Lookup />
        <Browser />
        <Tree />
      </div>
    );
  }
});

window.runApp = function() {
  React.render(<App />, document.getElementById('container'));
}
