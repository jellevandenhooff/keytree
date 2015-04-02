var React = require('react/addons');

var $ = require('jquery');
var _ = require('lodash');
var crypto = require('./crypto');

var downloadJson = function(url) {
  return Promise.resolve($.ajax(url, {dataType: 'json'}));
}

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
  fetch: async function(after) {
    this.setState({loading: true});
    try {
      var data = await downloadJson("/keytree/root");
      this.setState({loading: false, root: data});
    } catch (e) {
      this.setState({loading: false});
    }
  },
  componentDidMount: function() {
    this.fetch();
  },
  getInitialState: function() {
    return {root: undefined, loading: true};
  },
  render: function() {
    return (
      <div>
        <h1>Tree</h1>
        {this.state.loading ?
          <span>Loading...</span> : 
          <pre>{JSON.stringify(this.state.root, null, "  ")}</pre>}
      </div>
    );
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
